package integration

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/tunnel"
)

func TestSocks5RelayForwardingEcho(t *testing.T) {
	relayAddr := getFreeUDPAddr(t)

	relayServer, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new udp server failed: %v", err)
	}
	relayServer.AllowPrivateTargets = true

	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()

	relayErrCh := make(chan error, 1)
	go func() {
		relayErrCh <- relayServer.Start(relayCtx)
	}()

	time.Sleep(200 * time.Millisecond)

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	server := socks5.NewServer(":0")
	server.RequestTimeout = 5 * time.Second
	server.OnConnect = tunnel.NewRelayHandler(relayAddr, nil)

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	socksErrCh := make(chan error, 1)
	go func() {
		socksErrCh <- server.HandleConn(serverConn)
	}()

	if _, err := client.Write([]byte{socks5.Version5, 1, socks5.NoAuth}); err != nil {
		t.Fatalf("write greeting failed: %v", err)
	}

	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(client, methodResp); err != nil {
		t.Fatalf("read greeting response failed: %v", err)
	}

	host, port, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("split host port failed: %v", err)
	}

	req := append([]byte{socks5.Version5, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4}, net.ParseIP(host).To4()...)
	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		t.Fatalf("lookup port failed: %v", err)
	}
	req = append(req, byte(portNum>>8), byte(portNum))

	if _, err := client.Write(req); err != nil {
		t.Fatalf("write request failed: %v", err)
	}

	resp := make([]byte, 10)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read connect response failed: %v", err)
	}

	payload := []byte("nabu relay forwarding")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload failed: %v", err)
	}

	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echo); err != nil {
		t.Fatalf("read echo failed: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("unexpected echo: got=%q want=%q", string(echo), string(payload))
	}

	_ = client.Close()

	select {
	case err := <-socksErrCh:
		if err != nil {
			t.Fatalf("socks handler failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("socks handler did not stop")
	}

	relayCancel()
	select {
	case err := <-relayErrCh:
		if err != nil {
			t.Fatalf("relay server failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay server did not stop")
	}
}
