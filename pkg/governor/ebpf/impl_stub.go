// impl_stub.go — no-op Monitor backend used when the BPF object is not
// compiled (clang unavailable, non-Linux target, or CI without kernel).
//
// When bpf2go generates nabu_monitor_bpfeb.go / nabu_monitor_bpfel.go, the
// real backend in impl_linux.go is used instead (build tag: nabu_ebpf_real).
package ebpf

import (
	"context"
	"time"
)

// newImpl returns a stub implementation that performs no eBPF operations.
// All counters stay at zero; the event channel receives no events.
func newImpl() monitorImpl {
	return &stubImpl{}
}

// stubImpl satisfies monitorImpl with pure-Go no-ops.
type stubImpl struct{}

func (s *stubImpl) attach(_ string) error { return nil }

func (s *stubImpl) readEvents(ctx context.Context, _ chan<- Event) {
	// Block until context is cancelled so the caller's goroutine stays alive.
	<-ctx.Done()
}

func (s *stubImpl) counters() (Counter, Counter, error) {
	return Counter{}, Counter{}, nil
}

func (s *stubImpl) close() error { return nil }

// IsStub reports whether the Monitor is running on the no-op stub backend.
// Useful in tests and diagnostics.
func IsStub() bool { return true }

// StubSentinel is an Event injected by tests to verify the channel path.
var StubSentinel = Event{
	TimestampNS: uint64(time.Now().UnixNano()),
	IATNS:       0,
	PktLen:      64,
	Direction:   Ingress,
}
