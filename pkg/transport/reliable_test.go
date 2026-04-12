package transport

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

type fakePacketIO struct {
	mu      sync.Mutex
	sent    []Packet
	recv    []Packet
	recvErr []error
}

func (f *fakePacketIO) SendPacket(p Packet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, p)
	return nil
}

func (f *fakePacketIO) ReceivePacket() (Packet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.recvErr) > 0 {
		err := f.recvErr[0]
		f.recvErr = f.recvErr[1:]
		return Packet{}, err
	}
	if len(f.recv) == 0 {
		return Packet{}, fakeTimeoutErr{}
	}
	p := f.recv[0]
	f.recv = f.recv[1:]
	return p, nil
}

func (f *fakePacketIO) queueRecv(pkts ...Packet) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recv = append(f.recv, pkts...)
}

func (f *fakePacketIO) queueRecvErr(errs ...error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recvErr = append(f.recvErr, errs...)
}

func (f *fakePacketIO) sentPackets() []Packet {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Packet, len(f.sent))
	copy(out, f.sent)
	return out
}

func TestReliableSession_SendAndAck(t *testing.T) {
	fio := &fakePacketIO{}
	now := time.Unix(0, 0)
	s := NewReliableSession(fio, func() time.Time { return now })

	seq, err := s.SendData([]byte("hello"), 1)
	if err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if seq != 0 {
		t.Fatalf("first seq should be 0, got %d", seq)
	}

	if len(fio.sentPackets()) != 1 {
		t.Fatalf("expected one sent packet")
	}

	_, acked := s.HandleIncoming(BuildACK(seq, 2))
	if !acked {
		t.Fatal("expected acked=true for existing seq")
	}

	re, err := s.TickRetransmit()
	if err != nil {
		t.Fatalf("TickRetransmit: %v", err)
	}
	if re != 0 {
		t.Fatalf("expected no retransmit after ack, got %d", re)
	}
}

func TestReliableSession_ReassemblyAndDuplicateDrop(t *testing.T) {
	fio := &fakePacketIO{}
	s := NewReliableSession(fio, time.Now)

	out, _ := s.HandleIncoming(Packet{Seq: 1, Flags: PacketFlagData, Payload: []byte("b")})
	if len(out) != 0 {
		t.Fatalf("expected no output yet")
	}

	out, _ = s.HandleIncoming(Packet{Seq: 0, Flags: PacketFlagData, Payload: []byte("a")})
	if len(out) != 2 {
		t.Fatalf("expected 2 packets after in-order recovery, got %d", len(out))
	}

	out, _ = s.HandleIncoming(Packet{Seq: 0, Flags: PacketFlagData, Payload: []byte("dup")})
	if len(out) != 0 {
		t.Fatalf("duplicate should be dropped")
	}
}

func TestReliableSession_RetransmitOnTimeout(t *testing.T) {
	fio := &fakePacketIO{}
	now := time.Unix(0, 0)
	s := NewReliableSession(fio, func() time.Time { return now })

	_, err := s.SendData([]byte("x"), 1)
	if err != nil {
		t.Fatalf("SendData: %v", err)
	}

	// Initial RTO after one 100ms sample becomes ~300ms; wait beyond that.
	s.sendWindow.UpdateRTTEstimator(100 * time.Millisecond)
	now = now.Add(350 * time.Millisecond)

	re, err := s.TickRetransmit()
	if err != nil {
		t.Fatalf("TickRetransmit: %v", err)
	}
	if re != 1 {
		t.Fatalf("expected one retransmit, got %d", re)
	}
	if len(fio.sentPackets()) != 2 {
		t.Fatalf("expected original + retransmit, got %d", len(fio.sentPackets()))
	}
}

func TestReliableSession_DropAfterMaxRetries(t *testing.T) {
	fio := &fakePacketIO{}
	now := time.Unix(0, 0)
	s := NewReliableSession(fio, func() time.Time { return now })
	s.SetMaxRetries(1)

	_, err := s.SendData([]byte("x"), 1)
	if err != nil {
		t.Fatalf("SendData: %v", err)
	}
	s.sendWindow.UpdateRTTEstimator(100 * time.Millisecond)

	now = now.Add(350 * time.Millisecond)
	re, err := s.TickRetransmit()
	if err != nil {
		t.Fatalf("TickRetransmit #1: %v", err)
	}
	if re != 1 {
		t.Fatalf("expected first retransmit=1, got %d", re)
	}

	now = now.Add(350 * time.Millisecond)
	re, err = s.TickRetransmit()
	if err != nil {
		t.Fatalf("TickRetransmit #2: %v", err)
	}
	if re != 0 {
		t.Fatalf("expected dropped packet after max retries, got retransmit=%d", re)
	}
}

func TestReliableSession_ReceiveAndHandle_AutoACK(t *testing.T) {
	fio := &fakePacketIO{}
	s := NewReliableSession(fio, time.Now)

	fio.queueRecv(Packet{Seq: 0, Flags: PacketFlagData, Payload: []byte("a")})

	out, err := s.ReceiveAndHandle()
	if err != nil {
		t.Fatalf("ReceiveAndHandle: %v", err)
	}
	if len(out) != 1 || string(out[0].Payload) != "a" {
		t.Fatalf("unexpected reassembled output: %+v", out)
	}

	sent := fio.sentPackets()
	if len(sent) != 1 {
		t.Fatalf("expected one auto-ack packet, got %d", len(sent))
	}
	if sent[0].Flags&PacketFlagACK == 0 {
		t.Fatalf("expected ACK flag, got flags=0x%x", sent[0].Flags)
	}
	if sent[0].Seq != 0 {
		t.Fatalf("expected ack seq=0, got %d", sent[0].Seq)
	}
}

func TestReliableSession_RunReceiver_ReassemblesAndEmits(t *testing.T) {
	fio := &fakePacketIO{}
	s := NewReliableSession(fio, time.Now)

	out := make(chan Packet, 4)
	done := make(chan struct{})

	// Out-of-order delivery: seq=1 then seq=0. Receiver should emit 0,1 in order.
	fio.queueRecv(
		Packet{Seq: 1, Flags: PacketFlagData, Payload: []byte("b")},
		Packet{Seq: 0, Flags: PacketFlagData, Payload: []byte("a")},
	)

	go s.RunReceiver(done, out)

	p1 := <-out
	p2 := <-out
	close(done)

	if string(p1.Payload) != "a" || string(p2.Payload) != "b" {
		t.Fatalf("unexpected payload order: %q then %q", p1.Payload, p2.Payload)
	}

	acks := fio.sentPackets()
	if len(acks) < 2 {
		t.Fatalf("expected at least two ACK packets, got %d", len(acks))
	}
	if acks[0].Flags&PacketFlagACK == 0 || acks[1].Flags&PacketFlagACK == 0 {
		t.Fatalf("expected ACK flags on emitted control packets")
	}
}

func TestReliableSession_RunReceiver_ReportsNonTimeoutError(t *testing.T) {
	fio := &fakePacketIO{}
	s := NewReliableSession(fio, time.Now)

	done := make(chan struct{})
	out := make(chan Packet, 1)
	errCh := make(chan error, 2)
	s.SetErrorHandler(func(err error) {
		errCh <- err
	})

	fio.queueRecvErr(fmt.Errorf("boom"))

	go s.RunReceiver(done, out)

	select {
	case err := <-errCh:
		if err == nil || err.Error() != "boom" {
			t.Fatalf("unexpected error callback payload: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected non-timeout receive error to be reported")
	}
	close(done)
}
