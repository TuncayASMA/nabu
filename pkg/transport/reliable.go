package transport

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	DefaultRetransmitTick = 20 * time.Millisecond
	DefaultMaxRetries     = 3
)

// PacketIO is the minimal packet-level I/O contract used by ReliableSession.
type PacketIO interface {
	SendPacket(p Packet) error
	ReceivePacket() (Packet, error)
}

type pendingPacket struct {
	pkt     Packet
	retries int
}

// ReliableSession adds ACK tracking, in-order reassembly and timeout-based
// retransmission on top of packet-level UDP I/O.
type ReliableSession struct {
	io         PacketIO
	now        func() time.Time
	reasm      *Reassembler
	sendWindow *SendWindow

	retransmitTick time.Duration
	maxRetries     int

	mu      sync.Mutex
	nextSeq uint16
	pending map[uint16]*pendingPacket
	onError func(error)
}

func NewReliableSession(io PacketIO, now func() time.Time) *ReliableSession {
	if now == nil {
		now = time.Now
	}
	return &ReliableSession{
		io:             io,
		now:            now,
		reasm:          NewReassembler(DefaultWindowSize),
		sendWindow:     NewSendWindow(DefaultWindowSize, now),
		retransmitTick: DefaultRetransmitTick,
		maxRetries:     DefaultMaxRetries,
		pending:        make(map[uint16]*pendingPacket, DefaultWindowSize),
	}
}

func (s *ReliableSession) SetMaxRetries(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 1 {
		n = 1
	}
	s.maxRetries = n
}

func (s *ReliableSession) SetRetransmitTick(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d <= 0 {
		d = DefaultRetransmitTick
	}
	s.retransmitTick = d
}

// SetErrorHandler registers an optional callback for background loop errors.
// When nil, background errors are ignored.
func (s *ReliableSession) SetErrorHandler(fn func(error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onError = fn
}

// SendData sends a data packet and tracks it until ACK.
func (s *ReliableSession) SendData(payload []byte, timestamp uint32) (uint16, error) {
	s.mu.Lock()
	seq := s.nextSeq
	s.nextSeq++
	pkt := Packet{
		Seq:       seq,
		Flags:     PacketFlagData,
		Timestamp: timestamp,
		Payload:   append([]byte(nil), payload...),
	}
	s.pending[seq] = &pendingPacket{pkt: pkt}
	s.sendWindow.MarkSent(seq)
	s.mu.Unlock()

	if err := s.io.SendPacket(pkt); err != nil {
		return 0, err
	}
	return seq, nil
}

// BuildACK creates a standalone ACK packet for a received sequence.
func BuildACK(seq uint16, timestamp uint32) Packet {
	return Packet{Seq: seq, Flags: PacketFlagACK, Timestamp: timestamp}
}

// HandleIncoming processes one packet:
// - ACK packets clear pending retransmit state.
// - DATA packets are inserted into reassembler and may yield ordered output.
func (s *ReliableSession) HandleIncoming(pkt Packet) ([]Packet, bool) {
	if pkt.Flags&PacketFlagACK != 0 {
		s.mu.Lock()
		delete(s.pending, pkt.Seq)
		s.mu.Unlock()
		acked := s.sendWindow.Ack(pkt.Seq)
		return nil, acked
	}
	if pkt.Flags&PacketFlagData == 0 {
		return nil, false
	}
	out := s.reasm.Push(pkt)
	return out, false
}

// ReceiveAndHandle reads one packet from I/O, auto-sends ACK for DATA packets,
// then processes it through HandleIncoming.
func (s *ReliableSession) ReceiveAndHandle() ([]Packet, error) {
	pkt, err := s.io.ReceivePacket()
	if err != nil {
		return nil, err
	}

	if pkt.Flags&PacketFlagData != 0 {
		ack := BuildACK(pkt.Seq, uint32(s.now().Unix())) //nolint:gosec
		if err := s.io.SendPacket(ack); err != nil {
			return nil, fmt.Errorf("send ack seq=%d: %w", pkt.Seq, err)
		}
	}

	out, _ := s.HandleIncoming(pkt)
	return out, nil
}

// TickRetransmit checks all pending packets and retransmits timed-out ones.
// It returns the number of packets retransmitted in this tick.
func (s *ReliableSession) TickRetransmit() (int, error) {
	s.mu.Lock()
	maxRetries := s.maxRetries
	s.mu.Unlock()

	seqs := s.sendWindow.TrackedSeqs()
	retransmitted := 0

	for _, seq := range seqs {
		if !s.sendWindow.ShouldRetransmit(seq) {
			continue
		}

		s.mu.Lock()
		p, ok := s.pending[seq]
		if !ok {
			s.mu.Unlock()
			continue
		}
		if p.retries >= maxRetries {
			delete(s.pending, seq)
			s.sendWindow.Ack(seq)
			s.mu.Unlock()
			continue
		}
		pkt := p.pkt
		p.retries++
		s.sendWindow.MarkSent(seq)
		s.mu.Unlock()

		if err := s.io.SendPacket(pkt); err != nil {
			return retransmitted, fmt.Errorf("retransmit seq=%d: %w", seq, err)
		}
		retransmitted++
	}

	return retransmitted, nil
}

// Run starts a best-effort retransmit ticker loop and exits on context cancel.
func (s *ReliableSession) Run(ctxDone <-chan struct{}) {
	s.mu.Lock()
	tick := s.retransmitTick
	s.mu.Unlock()

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			_, err := s.TickRetransmit()
			if err != nil {
				s.reportError(err)
			}
		}
	}
}

// RunReceiver continuously receives packets, auto-acks DATA frames,
// reassembles in-order packets and emits them on out.
// Timeout errors are treated as expected polling behavior and ignored.
func (s *ReliableSession) RunReceiver(ctxDone <-chan struct{}, out chan<- Packet) {
	for {
		select {
		case <-ctxDone:
			return
		default:
		}

		reassembled, err := s.ReceiveAndHandle()
		if err != nil {
			if isTimeoutError(err) {
				continue
			}
			s.reportError(err)
			continue
		}

		for _, pkt := range reassembled {
			select {
			case <-ctxDone:
				return
			case out <- pkt:
			}
		}
	}
}

// RunIO starts both retransmit and receiver loops and blocks until ctxDone.
func (s *ReliableSession) RunIO(ctxDone <-chan struct{}, out chan<- Packet) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		s.Run(ctxDone)
	}()

	go func() {
		defer wg.Done()
		s.RunReceiver(ctxDone, out)
	}()

	wg.Wait()
}

func (s *ReliableSession) reportError(err error) {
	s.mu.Lock()
	h := s.onError
	s.mu.Unlock()
	if h != nil {
		h(err)
	}
}

func isTimeoutError(err error) bool {
	var nerr net.Error
	return err != nil && errors.As(err, &nerr) && nerr.Timeout()
}
