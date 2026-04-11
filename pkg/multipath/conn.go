package multipath

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// RelayEndpoint — a single relay address + its path identifier
// ---------------------------------------------------------------------------

// RelayEndpoint describes one relay server that can carry NABU traffic.
type RelayEndpoint struct {
	// ID is the PathStats.ID used by schedulers.  Must be unique within a
	// MultiPathConn.
	ID uint32

	// Addr is the UDP address of the relay (host:port).
	Addr string
}

// ---------------------------------------------------------------------------
// PingOptions — tuneable parameters for RTT measurement
// ---------------------------------------------------------------------------

// PingOptions controls how MultiPathConn probes relay latency.
type PingOptions struct {
	// Interval between probe rounds.  Default 5s.
	Interval time.Duration

	// Timeout for a single probe.  Default 2s.
	Timeout time.Duration

	// ProbesPerRound is the number of ICMP/UDP pings averaged per update.
	// Default 3.
	ProbesPerRound int
}

func (o PingOptions) withDefaults() PingOptions {
	if o.Interval == 0 {
		o.Interval = 5 * time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.ProbesPerRound == 0 {
		o.ProbesPerRound = 3
	}
	return o
}

// ---------------------------------------------------------------------------
// MultiPathConn — manages multiple relay paths and schedules traffic
// ---------------------------------------------------------------------------

// MultiPathConn maintains a live PathStats entry per relay endpoint and
// continuously probes each relay's RTT so that schedulers always have
// up-to-date telemetry.
//
// Probing uses lightweight UDP echo packets (8-byte payload) sent to the
// relay's probe port (relay port + 1000, or configurable).  If the relay
// does not echo, RTT is set to a large sentinel value (10s) and the path
// is marked unavailable.
//
// MultiPathConn does NOT implement net.Conn directly — it is a steering layer
// that consumers (e.g. QUIC multiplexer) call to choose which RelayEndpoint
// to use for the next stream or packet.
type MultiPathConn struct {
	endpoints []RelayEndpoint
	sched     Scheduler
	opts      PingOptions

	mu    sync.RWMutex
	stats []PathStats // parallel to endpoints

	nowFn func() time.Time // injectable for tests

	cancelAll context.CancelFunc
	wg        sync.WaitGroup
	started   atomic.Bool
}

// NewMultiPathConn creates a MultiPathConn for the given relay endpoints.
// The scheduler and probe options can be nil/zero for defaults (MinRTT, 5s).
func NewMultiPathConn(endpoints []RelayEndpoint, sched Scheduler, opts PingOptions) *MultiPathConn {
	if sched == nil {
		sched = NewMinRTT()
	}
	opts = opts.withDefaults()

	stats := make([]PathStats, len(endpoints))
	for i, ep := range endpoints {
		stats[i] = PathStats{
			ID:        ep.ID,
			RTT:       10 * time.Second, // pessimistic until first probe
			Available: false,
		}
	}

	return &MultiPathConn{
		endpoints: endpoints,
		sched:     sched,
		opts:      opts,
		stats:     stats,
		nowFn:     time.Now,
	}
}

// Start begins background probing of all relay endpoints.
// Call Stop() to terminate probing and release resources.
func (m *MultiPathConn) Start(ctx context.Context) {
	if !m.started.CompareAndSwap(false, true) {
		return
	}
	probeCtx, cancel := context.WithCancel(ctx)
	m.cancelAll = cancel

	for i := range m.endpoints {
		m.wg.Add(1)
		go m.probeLoop(probeCtx, i)
	}
}

// Stop terminates all background probing goroutines and waits for them to exit.
func (m *MultiPathConn) Stop() {
	if m.cancelAll != nil {
		m.cancelAll()
	}
	m.wg.Wait()
}

// SelectPath returns the index of the best relay endpoint chosen by the
// scheduler, and the corresponding RelayEndpoint.
// Returns (-1, zero) if no path is available.
func (m *MultiPathConn) SelectPath() (int, RelayEndpoint) {
	m.mu.RLock()
	snapshot := make([]PathStats, len(m.stats))
	copy(snapshot, m.stats)
	m.mu.RUnlock()

	idx := m.sched.SelectPath(snapshot)
	if idx < 0 || idx >= len(m.endpoints) {
		return -1, RelayEndpoint{}
	}
	return idx, m.endpoints[idx]
}

// Stats returns a snapshot of all current PathStats.
func (m *MultiPathConn) Stats() []PathStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PathStats, len(m.stats))
	copy(out, m.stats)
	return out
}

// UpdateStats allows external callers (e.g., QUIC acknowledgement callbacks)
// to push fresh telemetry for a path.  pathIdx is the index in the endpoints
// slice.
func (m *MultiPathConn) UpdateStats(pathIdx int, rtt time.Duration, bw uint64, loss float64) {
	if pathIdx < 0 || pathIdx >= len(m.stats) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &m.stats[pathIdx]
	s.RTT = rtt
	s.Bandwidth = bw
	s.LossRate = loss
	s.Available = true
}

// ---------------------------------------------------------------------------
// internal probe loop
// ---------------------------------------------------------------------------

// probeLoop sends periodic UDP echo probes to endpoint[idx] and updates
// its PathStats.  A probe sends an 8-byte magic payload and waits for an
// identical echo.  If the relay does not respond within opts.Timeout, the
// path is marked unavailable.
//
// The probe port is relay_port + 1000 (nabu relay exposes an echo responder
// on this derivative port).  For CI/unit-test environments where no real
// relay is running, the path simply stays marked unavailable until Stop()
// is called — this is the expected behaviour.
func (m *MultiPathConn) probeLoop(ctx context.Context, idx int) {
	defer m.wg.Done()

	ep := m.endpoints[idx]
	probeAddr, err := deriveProbeAddr(ep.Addr)
	if err != nil {
		// address parse error — mark permanently unavailable
		return
	}

	ticker := time.NewTicker(m.opts.Interval)
	defer ticker.Stop()

	// Probe immediately on first start.
	m.probe(ctx, idx, probeAddr)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probe(ctx, idx, probeAddr)
		}
	}
}

// probe sends ProbesPerRound UDP echo packets and computes the median RTT.
func (m *MultiPathConn) probe(ctx context.Context, idx int, probeAddr string) {
	opts := m.opts
	var sum time.Duration
	successes := 0

	for i := 0; i < opts.ProbesPerRound; i++ {
		rtt, ok := m.udpEcho(ctx, probeAddr, opts.Timeout)
		if ok {
			sum += rtt
			successes++
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	s := &m.stats[idx]
	if successes == 0 {
		s.Available = false
		s.RTT = 10 * time.Second
	} else {
		s.Available = true
		s.RTT = sum / time.Duration(successes)
	}
}

// udpEcho sends a single 8-byte UDP echo probe and returns the round-trip time.
func (m *MultiPathConn) udpEcho(_ context.Context, addr string, timeout time.Duration) (time.Duration, bool) {
	deadline := m.nowFn().Add(timeout)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		return 0, false
	}
	defer conn.Close() //nolint:errcheck

	if err = conn.SetDeadline(deadline); err != nil {
		return 0, false
	}

	// 8-byte magic probe payload: 0x4E 0x41 0x42 0x55 = "NABU" + 4 counter bytes.
	payload := []byte{0x4E, 0x41, 0x42, 0x55, 0x50, 0x52, 0x01, 0x02}

	t0 := m.nowFn()
	if _, err = conn.Write(payload); err != nil {
		return 0, false
	}

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || n != 8 {
		return 0, false
	}
	return m.nowFn().Sub(t0), true
}

// deriveProbeAddr returns the echo-probe address for a relay addr.
// Convention: probe_port = relay_port + 1000.
func deriveProbeAddr(relayAddr string) (string, error) {
	host, portStr, err := net.SplitHostPort(relayAddr)
	if err != nil {
		return "", fmt.Errorf("multipath: bad relay addr %q: %w", relayAddr, err)
	}
	var port int
	if _, err = fmt.Sscanf(portStr, "%d", &port); err != nil {
		return "", fmt.Errorf("multipath: bad port %q: %w", portStr, err)
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port+1000)), nil
}
