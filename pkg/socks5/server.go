package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

const (
	Version5   = 0x05
	NoAuth     = 0x00
	NoAccept   = 0xFF
	CmdConnect = 0x01

	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04

	DefaultMaxConns         = 1024
	DefaultHandshakeTimeout = 5 * time.Second
	DefaultRequestTimeout   = 30 * time.Second
	MaxAuthMethods          = 16
)

var (
	ErrInvalidVersion    = errors.New("invalid socks version")
	ErrNoMethods         = errors.New("no auth methods provided")
	ErrNoSupportedMethod = errors.New("no supported auth method")
	ErrTooManyMethods    = errors.New("too many auth methods")
	ErrUnsupportedCmd    = errors.New("unsupported socks command")
	ErrInvalidAddrType   = errors.New("invalid address type")
)

type Request struct {
	Command byte
	Host    string
	Port    uint16
}

type Server struct {
	ListenAddr       string
	MaxConns         int
	HandshakeTimeout time.Duration
	RequestTimeout   time.Duration
	Logger           *slog.Logger

	connSem chan struct{}
}

func NewServer(listenAddr string) *Server {
	return &Server{
		ListenAddr:       listenAddr,
		MaxConns:         DefaultMaxConns,
		HandshakeTimeout: DefaultHandshakeTimeout,
		RequestTimeout:   DefaultRequestTimeout,
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}

func (s *Server) ListenAndServe() error {
	return s.ListenAndServeContext(context.Background())
}

func (s *Server) ListenAndServeContext(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if s.MaxConns <= 0 {
		s.MaxConns = DefaultMaxConns
	}
	if s.HandshakeTimeout <= 0 {
		s.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if s.RequestTimeout <= 0 {
		s.RequestTimeout = DefaultRequestTimeout
	}
	if s.Logger == nil {
		s.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	s.connSem = make(chan struct{}, s.MaxConns)

	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("accept failed: %w", err)
		}

		s.connSem <- struct{}{}
		wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					s.Logger.Error("panic in socks5 handler", "remote", c.RemoteAddr().String(), "recover", r, "stack", string(debug.Stack()))
				}
				_ = c.Close()
				<-s.connSem
				wg.Done()
			}()

			if err := s.HandleConn(c); err != nil {
				s.Logger.Warn("connection closed with error", "remote", c.RemoteAddr().String(), "error", err)
			}
		}(conn)
	}
}

func (s *Server) HandleConn(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(s.HandshakeTimeout)); err != nil {
		return fmt.Errorf("set handshake deadline failed: %w", err)
	}

	r := bufio.NewReader(conn)

	method, err := ReadGreeting(r)
	if err != nil {
		return err
	}
	if _, err := conn.Write([]byte{Version5, method}); err != nil {
		return fmt.Errorf("write greeting response failed: %w", err)
	}
	if method == NoAccept {
		return ErrNoSupportedMethod
	}

	if err := conn.SetReadDeadline(time.Now().Add(s.RequestTimeout)); err != nil {
		return fmt.Errorf("set request deadline failed: %w", err)
	}

	req, err := ReadRequest(r)
	if err != nil {
		return err
	}

	s.Logger.Info("socks5 request received", "remote", conn.RemoteAddr().String(), "host", req.Host, "port", req.Port)

	// Send success response (0x05 0x00 = no error).
	// Format: version=0x05, reply=0x00, reserved=0x00, addrtype, bindaddr (4), bindport (2)
	respBuf := []byte{Version5, 0x00, 0x00, AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(respBuf); err != nil {
		return fmt.Errorf("write socks5 response failed: %w", err)
	}

	// TODO: Forward request to relay transport layer
	// 1. Create transport stream to relay
	// 2. Pipe client conn ↔ relay stream
	// 3. Handle graceful shutdown
	return nil
}

func ReadRequest(r io.Reader) (Request, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return Request{}, fmt.Errorf("read request header failed: %w", err)
	}

	if head[0] != Version5 {
		return Request{}, ErrInvalidVersion
	}
	if head[2] != 0x00 {
		return Request{}, fmt.Errorf("invalid reserved field: expected 0x00, got 0x%02x", head[2])
	}
	if head[1] != CmdConnect {
		return Request{}, ErrUnsupportedCmd
	}

	addrType := head[3]
	host, err := readAddressByType(r, addrType)
	if err != nil {
		return Request{}, err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return Request{}, fmt.Errorf("read request port failed: %w", err)
	}
	port := uint16(portBuf[0])<<8 | uint16(portBuf[1])

	return Request{Command: CmdConnect, Host: host, Port: port}, nil
}

func readAddressByType(r io.Reader, addrType byte) (string, error) {
	switch addrType {
	case AddrTypeIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("read ipv4 address failed: %w", err)
		}
		return net.IP(b).String(), nil
	case AddrTypeIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("read ipv6 address failed: %w", err)
		}
		return net.IP(b).String(), nil
	case AddrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length failed: %w", err)
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			return "", ErrInvalidAddrType
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", fmt.Errorf("read domain failed: %w", err)
		}
		for _, b := range domain {
			if b == 0 || b < 0x21 || b > 0x7E {
				return "", ErrInvalidAddrType
			}
		}
		return string(domain), nil
	default:
		return "", ErrInvalidAddrType
	}
}

func ReadGreeting(r io.Reader) (byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, fmt.Errorf("read greeting header failed: %w", err)
	}

	if head[0] != Version5 {
		return 0, ErrInvalidVersion
	}
	nMethods := int(head[1])
	if nMethods == 0 {
		return 0, ErrNoMethods
	}
	if nMethods > MaxAuthMethods {
		return 0, ErrTooManyMethods
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return 0, fmt.Errorf("read methods failed: %w", err)
	}

	for _, m := range methods {
		if m == NoAuth {
			return NoAuth, nil
		}
	}

	return NoAccept, nil
}
