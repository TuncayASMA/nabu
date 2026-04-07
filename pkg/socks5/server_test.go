package socks5

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestReadGreetingNoAuth(t *testing.T) {
	input := []byte{Version5, 1, NoAuth}
	method, err := ReadGreeting(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}
	if method != NoAuth {
		t.Fatalf("expected no-auth method, got=%d", method)
	}
}

func TestReadGreetingRejectsInvalidVersion(t *testing.T) {
	input := []byte{0x04, 1, NoAuth}
	_, err := ReadGreeting(bytes.NewReader(input))
	if !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("expected invalid version error, got=%v", err)
	}
}

func TestReadGreetingNoMethods(t *testing.T) {
	input := []byte{Version5, 0}
	_, err := ReadGreeting(bytes.NewReader(input))
	if !errors.Is(err, ErrNoMethods) {
		t.Fatalf("expected no methods error, got=%v", err)
	}
}

func TestReadGreetingNoSupportedMethod(t *testing.T) {
	input := []byte{Version5, 2, 0x02, 0x03}
	method, err := ReadGreeting(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if method != NoAccept {
		t.Fatalf("expected no acceptable method, got=%d", method)
	}
}

func TestReadGreetingTooManyMethods(t *testing.T) {
	methods := make([]byte, MaxAuthMethods+1)
	input := append([]byte{Version5, byte(MaxAuthMethods + 1)}, methods...)
	_, err := ReadGreeting(bytes.NewReader(input))
	if !errors.Is(err, ErrTooManyMethods) {
		t.Fatalf("expected too many methods error, got=%v", err)
	}
}

func TestHandleConnWritesMethodSelection(t *testing.T) {
	s := NewServer(":0")
	s.RequestTimeout = 200 * time.Millisecond
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.HandleConn(server)
	}()

	if _, err := client.Write([]byte{Version5, 1, NoAuth}); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := client.Read(resp); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if !bytes.Equal(resp, []byte{Version5, NoAuth}) {
		t.Fatalf("unexpected method response: %v", resp)
	}

	// Send minimal CONNECT request (example.com:80)
	domain := "example.com"
	req := append([]byte{Version5, CmdConnect, 0x00, AddrTypeDomain, byte(len(domain))}, []byte(domain)...)
	req = append(req, 0x00, 0x50)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write request failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("handle conn failed: %v", err)
	}
}

func TestHandleConnNoSupportedMethod(t *testing.T) {
	s := NewServer(":0")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.HandleConn(server)
	}()

	if _, err := client.Write([]byte{Version5, 1, 0x02}); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := client.Read(resp); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if !bytes.Equal(resp, []byte{Version5, NoAccept}) {
		t.Fatalf("unexpected method response: %v", resp)
	}

	if err := <-errCh; !errors.Is(err, ErrNoSupportedMethod) {
		t.Fatalf("expected no supported method error, got=%v", err)
	}
}

func TestReadRequestIPv4Connect(t *testing.T) {
	// VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST=1.2.3.4, PORT=443
	input := []byte{Version5, CmdConnect, 0x00, AddrTypeIPv4, 1, 2, 3, 4, 0x01, 0xBB}
	req, err := ReadRequest(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	if req.Host != "1.2.3.4" {
		t.Fatalf("unexpected host: %s", req.Host)
	}
	if req.Port != 443 {
		t.Fatalf("unexpected port: %d", req.Port)
	}
}

func TestReadRequestDomainConnect(t *testing.T) {
	domain := "example.com"
	input := append([]byte{Version5, CmdConnect, 0x00, AddrTypeDomain, byte(len(domain))}, []byte(domain)...)
	input = append(input, 0x00, 0x50) // 80
	req, err := ReadRequest(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	if req.Host != domain {
		t.Fatalf("unexpected host: %s", req.Host)
	}
	if req.Port != 80 {
		t.Fatalf("unexpected port: %d", req.Port)
	}
}

func TestReadRequestRejectsUnsupportedCommand(t *testing.T) {
	input := []byte{Version5, 0x02, 0x00, AddrTypeIPv4, 1, 1, 1, 1, 0x00, 0x50}
	_, err := ReadRequest(bytes.NewReader(input))
	if !errors.Is(err, ErrUnsupportedCmd) {
		t.Fatalf("expected unsupported cmd error, got=%v", err)
	}
}

func TestReadRequestIPv6Connect(t *testing.T) {
	ipv6 := net.ParseIP("::1").To16()
	input := append([]byte{Version5, CmdConnect, 0x00, AddrTypeIPv6}, ipv6...)
	input = append(input, 0x00, 0x50)

	req, err := ReadRequest(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	if req.Host != "::1" {
		t.Fatalf("unexpected host: %s", req.Host)
	}
	if req.Port != 80 {
		t.Fatalf("unexpected port: %d", req.Port)
	}
}

func TestReadRequestRejectsNonZeroReserved(t *testing.T) {
	input := []byte{Version5, CmdConnect, 0x01, AddrTypeIPv4, 1, 1, 1, 1, 0x00, 0x50}
	_, err := ReadRequest(bytes.NewReader(input))
	if err == nil {
		t.Fatal("expected error for non-zero reserved byte")
	}
}

func TestReadRequestRejectsInvalidDomainChars(t *testing.T) {
	input := []byte{Version5, CmdConnect, 0x00, AddrTypeDomain, 3, 'a', 0x00, 'b', 0x00, 0x50}
	_, err := ReadRequest(bytes.NewReader(input))
	if !errors.Is(err, ErrInvalidAddrType) {
		t.Fatalf("expected invalid addr type error, got=%v", err)
	}
}
