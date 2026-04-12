package transport

import (
	"net"
	"testing"
	"time"
)

func TestReliableSession_UDPLoopbackACKFlow(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	// Echo-ACK server: every DATA packet is answered with ACK(seq).
	go func() {
		buf := make([]byte, PacketHeaderSize+MaxUDPPayload+PacketCRCSize)
		for {
			n, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			pkt, decErr := DecodePacket(buf[:n])
			if decErr != nil {
				continue
			}
			if pkt.Flags&PacketFlagData == 0 {
				continue
			}
			ack := BuildACK(pkt.Seq, pkt.Timestamp)
			raw, encErr := EncodePacket(ack)
			if encErr != nil {
				continue
			}
			pc.WriteTo(raw, addr) //nolint:errcheck
		}
	}()

	client, err := NewUDPClient(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	if err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	client.ReadTimeout = 2 * time.Second

	s := NewReliableSession(client, time.Now)
	seq, err := s.SendData([]byte("hello"), 100)
	if err != nil {
		t.Fatalf("SendData: %v", err)
	}

	ackPkt, err := client.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket ack: %v", err)
	}
	if ackPkt.Flags&PacketFlagACK == 0 {
		t.Fatalf("expected ACK packet, got flags=0x%x", ackPkt.Flags)
	}
	if ackPkt.Seq != seq {
		t.Fatalf("ack seq mismatch: got=%d want=%d", ackPkt.Seq, seq)
	}

	_, acked := s.HandleIncoming(ackPkt)
	if !acked {
		t.Fatal("expected acked=true for loopback ack")
	}

	re, err := s.TickRetransmit()
	if err != nil {
		t.Fatalf("TickRetransmit: %v", err)
	}
	if re != 0 {
		t.Fatalf("expected no retransmit after ack, got %d", re)
	}
}
