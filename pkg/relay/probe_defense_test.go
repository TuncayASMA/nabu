package relay

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeConn implements net.Conn; WriteBuffer accumulates written bytes.
type fakeConn struct {
	net.Conn
	ReadBuffer *bufio.Reader
	Written    []byte
	remoteAddr net.Addr
}

func newFakeConn(data string, remoteAddr string) *fakeConn {
	return &fakeConn{
		ReadBuffer: bufio.NewReader(strings.NewReader(data)),
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	}
}

func newFakeConnWithAddr(data string, remoteIP string, port int) *fakeConn {
	return &fakeConn{
		ReadBuffer: bufio.NewReader(strings.NewReader(data)),
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: port},
	}
}

func (f *fakeConn) Read(b []byte) (int, error) { return f.ReadBuffer.Read(b) }
func (f *fakeConn) Write(b []byte) (int, error) {
	f.Written = append(f.Written, b...)
	return len(b), nil
}
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) RemoteAddr() net.Addr             { return f.remoteAddr }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestProbeDefenseDecoyIndex(t *testing.T) {
	pd := NewProbeDefense()
	conn := newFakeConn("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "127.0.0.1:9999")
	pd.HandleProbe(conn, conn.ReadBuffer)

	resp := string(conn.Written)
	if !strings.Contains(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200 OK, got: %s", resp)
	}
	if !strings.Contains(resp, "Mehmet Yilmaz") {
		t.Fatalf("expected decoy body, got: %s", resp)
	}
	if !strings.Contains(resp, "nginx/1.24.0") {
		t.Fatalf("expected nginx Server header, got: %s", resp)
	}
}

func TestProbeDefenseDecoyAbout(t *testing.T) {
	pd := NewProbeDefense()
	conn := newFakeConn("GET /about HTTP/1.1\r\nHost: example.com\r\n\r\n", "127.0.0.1:9999")
	pd.HandleProbe(conn, conn.ReadBuffer)

	resp := string(conn.Written)
	if !strings.Contains(resp, "About Me") {
		t.Fatalf("expected /about body, got: %s", resp)
	}
}

func TestProbeDefenseDecoyBlog(t *testing.T) {
	pd := NewProbeDefense()
	conn := newFakeConn("GET /blog HTTP/1.1\r\nHost: example.com\r\n\r\n", "127.0.0.1:9999")
	pd.HandleProbe(conn, conn.ReadBuffer)

	resp := string(conn.Written)
	if !strings.Contains(resp, "Blog") {
		t.Fatalf("expected /blog body, got: %s", resp)
	}
}

func TestProbeDefenseNonHTTPSilentClose(t *testing.T) {
	pd := NewProbeDefense()
	// Binary garbage — not HTTP.
	conn := newFakeConn("\x00\x01\x02\x03\xff\xfe", "127.0.0.1:9999")
	pd.HandleProbe(conn, conn.ReadBuffer)

	// Should write nothing — silent close.
	if len(conn.Written) != 0 {
		t.Fatalf("expected no response to non-HTTP data, got %d bytes", len(conn.Written))
	}
}

func TestProbeDefenseBanAfterThreshold(t *testing.T) {
	pd := NewProbeDefense()
	pd.BanThreshold = 3
	pd.BanWindow = time.Minute
	pd.BanDuration = time.Hour

	ip := "10.0.0.1"

	// First BanThreshold-1 probes: not yet banned, get decoy.
	for i := 0; i < pd.BanThreshold-1; i++ {
		conn := newFakeConnWithAddr("GET / HTTP/1.1\r\nHost: x\r\n\r\n", ip, 1000+i)
		pd.HandleProbe(conn, conn.ReadBuffer)
		if len(conn.Written) == 0 {
			t.Fatalf("probe %d: expected decoy response before ban", i+1)
		}
	}

	// BanThreshold-th probe: this one triggers the ban (recordFailure sets bannedUntil after this call).
	conn := newFakeConnWithAddr("GET / HTTP/1.1\r\nHost: x\r\n\r\n", ip, 2000)
	pd.HandleProbe(conn, conn.ReadBuffer)
	// The ban is set after counting this failure, but the response is still served
	// (ban check happens before recordFailure, so this request gets a response).

	// Next probe: banned — no response.
	conn2 := newFakeConnWithAddr("GET / HTTP/1.1\r\nHost: x\r\n\r\n", ip, 2001)
	pd.HandleProbe(conn2, conn2.ReadBuffer)
	if len(conn2.Written) != 0 {
		t.Fatalf("expected silent drop for banned IP, got %d bytes", len(conn2.Written))
	}
}

func TestProbeDefenseIsBanned(t *testing.T) {
	pd := NewProbeDefense()
	pd.BanThreshold = 1
	pd.BanDuration = time.Hour

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000}
	if pd.IsBanned(addr) {
		t.Fatal("should not be banned initially")
	}

	conn := newFakeConnWithAddr("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "192.168.1.1", 5000)
	pd.HandleProbe(conn, conn.ReadBuffer)

	if !pd.IsBanned(addr) {
		t.Fatal("should be banned after threshold reached")
	}
}

func TestProbeDefenseWindowReset(t *testing.T) {
	pd := NewProbeDefense()
	pd.BanThreshold = 3
	pd.BanWindow = 50 * time.Millisecond
	pd.BanDuration = time.Hour

	ip := "172.16.0.1"

	// Send BanThreshold-1 failures.
	for i := 0; i < pd.BanThreshold-1; i++ {
		conn := newFakeConnWithAddr("GET / HTTP/1.1\r\nHost: x\r\n\r\n", ip, 3000+i)
		pd.HandleProbe(conn, conn.ReadBuffer)
	}

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)

	// Counter should reset — not banned after threshold more probes (window restarted).
	for i := 0; i < pd.BanThreshold-1; i++ {
		conn := newFakeConnWithAddr("GET / HTTP/1.1\r\nHost: x\r\n\r\n", ip, 4000+i)
		pd.HandleProbe(conn, conn.ReadBuffer)
	}

	addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 9999}
	if pd.IsBanned(addr) {
		t.Fatal("should NOT be banned: window reset between attempts")
	}
}
