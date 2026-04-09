package relay

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ProbeDefense serves innocuous-looking HTTP/1.1 responses to connections that
// fail the NABU handshake.  From the outside the relay looks like a static blog.
// It also tracks failed probe attempts per source IP and silently drops
// connections once an IP exceeds BanThreshold within BanWindow.
//
// Usage: set TCPServer.ProbeDefense to a *ProbeDefense instance.  When a
// connection fails the initial NABU handshake, handleConn calls HandleProbe;
// the rest of the connection lifecycle is managed by ProbeDefense.
type ProbeDefense struct {
	// BanThreshold is the number of failed NABU handshakes from a single IP
	// within BanWindow before the IP is silently rejected. Default: 5.
	BanThreshold int
	// BanWindow is the observation window for failure counting. Default: 5 min.
	BanWindow time.Duration
	// BanDuration is how long a banned IP is silently dropped. Default: 30 min.
	BanDuration time.Duration

	mu      sync.Mutex
	tracker map[string]*probeEntry // key = bare IP (no port)
}

type probeEntry struct {
	count       int
	windowStart time.Time
	bannedUntil time.Time
}

// NewProbeDefense returns a ProbeDefense with default thresholds.
func NewProbeDefense() *ProbeDefense {
	return &ProbeDefense{
		BanThreshold: 5,
		BanWindow:    5 * time.Minute,
		BanDuration:  30 * time.Minute,
		tracker:      make(map[string]*probeEntry),
	}
}

// HandleProbe is called when a connection fails the NABU handshake.
// It records the failure, checks the ban list, and optionally serves a decoy
// HTTP response.  reader must be the bufio.Reader wrapping conn so that any
// already-buffered bytes from failed frame reads are available.
// HandleProbe always closes conn before returning.
func (pd *ProbeDefense) HandleProbe(conn net.Conn, reader *bufio.Reader) {
	defer conn.Close()

	ip := extractIP(conn.RemoteAddr())
	if pd.isBanned(ip) {
		// Silent drop — no response, just close.
		return
	}
	pd.recordFailure(ip)

	// Try to parse an HTTP/1.1 request from whatever bytes the client sent.
	req, err := http.ReadRequest(reader)
	if err != nil {
		// Not an HTTP request — close silently (don't fingerprint ourselves).
		return
	}

	body := decoyBody(req.URL.Path)
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\nServer: nginx/1.24.0\r\n\r\n%s",
		len(body), body,
	)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(resp))
}

// IsBanned reports whether the given remote address is currently banned.
func (pd *ProbeDefense) IsBanned(addr net.Addr) bool {
	return pd.isBanned(extractIP(addr))
}

// ResetBan removes any ban / failure record for the given address (test helper).
func (pd *ProbeDefense) ResetBan(addr string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	delete(pd.tracker, addr)
}

func (pd *ProbeDefense) isBanned(ip string) bool {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	e, ok := pd.tracker[ip]
	if !ok {
		return false
	}
	return time.Now().Before(e.bannedUntil)
}

func (pd *ProbeDefense) recordFailure(ip string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	now := time.Now()
	e, ok := pd.tracker[ip]
	if !ok {
		e = &probeEntry{windowStart: now}
		pd.tracker[ip] = e
	}
	// Reset window if expired.
	if now.Sub(e.windowStart) > pd.BanWindow {
		e.count = 0
		e.windowStart = now
	}
	e.count++
	if e.count >= pd.BanThreshold {
		e.bannedUntil = now.Add(pd.BanDuration)
	}
}

// extractIP returns the host part of a net.Addr string (strips port).
func extractIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// IsHTTPMethodPrefix returns true when the 4-byte prefix matches a common
// HTTP/1.1 method.  Used by TCPServer to detect active probers before
// attempting NABU frame parsing.
func IsHTTPMethodPrefix(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch string(b[:4]) {
	case "GET ", "POST", "HEAD", "CONN", "OPTI", "PUT ", "DELE", "PATC", "TRAC":
		return true
	}
	return false
}

// decoyBody returns the HTML body for the given URL path.
func decoyBody(path string) string {
	switch {
	case strings.HasPrefix(path, "/about"):
		return decoyAbout
	case strings.HasPrefix(path, "/blog"):
		return decoyBlog
	default:
		return decoyIndex
	}
}

const decoyIndex = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Mehmet Yilmaz — Blog</title></head>
<body>
<h1>Welcome</h1>
<p>Personal blog about software, travel, and coffee.</p>
<nav><a href="/about">About</a> &bull; <a href="/blog">Blog</a></nav>
</body>
</html>`

const decoyAbout = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>About — Mehmet Yilmaz</title></head>
<body>
<h1>About Me</h1>
<p>Software developer based in Istanbul. I write about Go, Linux and distributed systems.</p>
</body>
</html>`

const decoyBlog = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Blog — Mehmet Yilmaz</title></head>
<body>
<h1>Blog</h1>
<ul>
<li><a href="/blog/hello-world">Hello World</a></li>
<li><a href="/blog/go-tips">Go Tips &amp; Tricks</a></li>
</ul>
</body>
</html>`
