// Package ebpf provides a Go wrapper around the NABU eBPF traffic monitor.
//
// The eBPF object nabu_monitor.bpf.o is compiled from nabu_monitor.c via:
//
//	go generate ./pkg/governor/ebpf/
//
// which runs bpf2go and embeds the compiled BPF object into nabu_monitor_bpfeb.go
// and nabu_monitor_bpfel.go (big/little endian variants).
//
// On systems where the BPF object has not been compiled yet (e.g. CI without
// clang), the loader falls back to a no-op stub so the rest of the codebase
// can still build and unit-test.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -target bpf -D__TARGET_ARCH_arm64" nabuMonitor bpf/nabu_monitor.c -- -I/usr/include/aarch64-linux-gnu
package ebpf

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Direction identifies packet flow relative to the monitored interface.
type Direction uint8

const (
	Ingress Direction = 0
	Egress  Direction = 1
)

// Event is a single packet observation reported by the eBPF program.
type Event struct {
	TimestampNS uint64    // absolute monotonic timestamp (CLOCK_MONOTONIC)
	IATNS       uint64    // inter-arrival time from previous packet; 0 for first
	PktLen      uint32    // packet length in bytes
	Direction   Direction // Ingress or Egress
}

// Counter holds the aggregate counters for one direction.
type Counter struct {
	Packets uint64
	Bytes   uint64
}

// Snapshot is a point-in-time read of both ingress and egress counters.
type Snapshot struct {
	At      time.Time
	Ingress Counter
	Egress  Counter
}

// Monitor manages the lifecycle of the NABU eBPF traffic monitor.
// It attaches TC clsact hooks to the named network interface, reads
// packet events from the BPF ring buffer, and maintains running counters.
type Monitor struct {
	iface  string
	events chan Event

	mu      sync.RWMutex
	ingress Counter
	egress  Counter

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// impl is the platform-specific backend (real eBPF or no-op stub).
	impl monitorImpl
}

// monitorImpl is the internal interface satisfied by both the real eBPF
// backend and the no-op stub used when eBPF is unavailable.
type monitorImpl interface {
	// attach loads the BPF object and attaches TC hooks to iface.
	attach(iface string) error
	// readEvents blocks and forwards raw events to ch until ctx is cancelled.
	readEvents(ctx context.Context, ch chan<- Event)
	// counters returns the BPF map counters for ingress (idx 0) and egress (idx 1).
	counters() (ingress Counter, egress Counter, err error)
	// close detaches TC hooks and frees BPF resources.
	close() error
}

// NewMonitor creates a Monitor for the given network interface name.
// The eventBufSize controls how many Events can queue before blocking.
func NewMonitor(iface string, eventBufSize int) *Monitor {
	return &Monitor{
		iface:  iface,
		events: make(chan Event, eventBufSize),
		impl:   newImpl(),
	}
}

// Start attaches the eBPF programs and begins reading events.
// It is idempotent: calling Start on an already-started Monitor is a no-op.
func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return nil // already started
	}

	if err := m.impl.attach(m.iface); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("ebpf monitor: attach %q: %w", m.iface, err)
	}

	ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()

	m.wg.Add(2)

	// Ring buffer reader goroutine.
	go func() {
		defer m.wg.Done()
		m.impl.readEvents(ctx, m.events)
	}()

	// Counter aggregator goroutine: keeps in-memory counters in sync.
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ing, eg, err := m.impl.counters()
				if err == nil {
					m.mu.Lock()
					m.ingress = ing
					m.egress = eg
					m.mu.Unlock()
				}
			}
		}
	}()

	return nil
}

// Stop detaches the eBPF programs and drains the event channel.
func (m *Monitor) Stop() error {
	m.mu.Lock()
	if m.cancel == nil {
		m.mu.Unlock()
		return nil
	}
	m.cancel()
	m.cancel = nil
	m.mu.Unlock()

	m.wg.Wait()

	var errs []error
	if err := m.impl.close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Events returns a read-only channel of packet events.
func (m *Monitor) Events() <-chan Event {
	return m.events
}

// Snapshot returns the latest ingress/egress counter values.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{
		At:      time.Now(),
		Ingress: m.ingress,
		Egress:  m.egress,
	}
}
