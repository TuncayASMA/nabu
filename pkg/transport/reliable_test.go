package transport

import (
	"sync"
	"testing"
	"time"
)

type fakePacketIO struct {
	mu   sync.Mutex
	sent []Packet
}

func (f *fakePacketIO) SendPacket(p Packet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, p)
	return nil
}

func (f *fakePacketIO) ReceivePacket() (Packet, error) { return Packet{}, nil }

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
