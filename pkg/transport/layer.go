package transport

import "time"

// Layer is the abstraction that each transport implementation must satisfy.
// The current implementation (UDPClient) satisfies Frame-level I/O.
// Faz-2 obfuscation wrappers will implement this interface to sit between
// the tunnel logic and the raw UDP socket.
//
// Design rationale:
//   - Keep it minimal: SendFrame + ReceiveFrame + Close covers all call sites.
//   - MeasureRTT is omitted intentionally — it is an optional optimisation
//     implemented by concrete transports that support Ping/Pong; callers
//     type-assert to RTTMeasurer when they need it.
type Layer interface {
	// SendFrame encodes and transmits a single frame.
	SendFrame(f Frame) error

	// ReceiveFrame blocks until a frame arrives or an error occurs.
	ReceiveFrame() (Frame, error)

	// Close releases any resources held by the transport.
	Close() error
}

// RTTMeasurer is an optional capability that a Layer may expose.
// Callers check for this with a type assertion; absence is not an error.
type RTTMeasurer interface {
	// MeasureRTT sends a Ping frame and returns the round-trip time.
	MeasureRTT(streamID uint16, seq uint32) (time.Duration, error)
}

// ReadTimeoutSetter is an optional capability allowing callers to adjust the
// per-frame receive deadline of a transport layer.  UDPClient implements this;
// obfuscation layers may delegate it to the underlying layer.
type ReadTimeoutSetter interface {
	SetReadTimeout(d time.Duration)
}
