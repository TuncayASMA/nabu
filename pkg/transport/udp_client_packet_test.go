package transport

import (
	"net"
	"testing"
	"time"
)

func TestUDPClient_SendPacket_NotConnected(t *testing.T) {
	client, err := NewUDPClient("127.0.0.1:9")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	err = client.SendPacket(Packet{Seq: 1, Flags: PacketFlagData, Timestamp: 1, Payload: []byte("x")})
	if err == nil {
		t.Fatal("expected not connected error")
	}
}

func TestUDPClient_SendReceivePacket(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, PacketHeaderSize+MaxUDPPayload+PacketCRCSize)
		for {
			n, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			pc.WriteTo(buf[:n], addr) //nolint:errcheck
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

	in := Packet{Seq: 7, Flags: PacketFlagData, Timestamp: 123, Payload: []byte("payload")}
	if err := client.SendPacket(in); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}

	out, err := client.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	if out.Seq != in.Seq || out.Flags != in.Flags || out.Timestamp != in.Timestamp {
		t.Fatalf("header mismatch: got=%+v want=%+v", out, in)
	}
	if string(out.Payload) != string(in.Payload) {
		t.Fatalf("payload mismatch: got=%q want=%q", out.Payload, in.Payload)
	}
}

func TestUDPClient_SendPayloadFragments(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	recv := make(chan Packet, 8)
	go func() {
		buf := make([]byte, PacketHeaderSize+MaxUDPPayload+PacketCRCSize)
		for {
			n, _, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			pkt, decErr := DecodePacket(buf[:n])
			if decErr != nil {
				continue
			}
			recv <- pkt
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

	payload := make([]byte, MaxUDPPayload+120)
	n, err := client.SendPayloadFragments(PacketFlagData, 77, payload)
	if err != nil {
		t.Fatalf("SendPayloadFragments: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 fragments, got %d", n)
	}

	got1 := <-recv
	got2 := <-recv
	if got2.Seq != got1.Seq+1 {
		t.Fatalf("expected sequential packet seq, got %d then %d", got1.Seq, got2.Seq)
	}
	if len(got1.Payload) > MaxUDPPayload || len(got2.Payload) > MaxUDPPayload {
		t.Fatalf("fragment exceeds MTU-safe payload: %d, %d", len(got1.Payload), len(got2.Payload))
	}
}

func TestUDPClient_SendPayloadFragments_SequenceContinuesAcrossCalls(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	recv := make(chan Packet, 8)
	go func() {
		buf := make([]byte, PacketHeaderSize+MaxUDPPayload+PacketCRCSize)
		for {
			n, _, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			pkt, decErr := DecodePacket(buf[:n])
			if decErr != nil {
				continue
			}
			recv <- pkt
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

	payload := make([]byte, MaxUDPPayload+10)
	n1, err := client.SendPayloadFragments(PacketFlagData, 10, payload)
	if err != nil {
		t.Fatalf("first SendPayloadFragments: %v", err)
	}
	n2, err := client.SendPayloadFragments(PacketFlagData, 11, payload)
	if err != nil {
		t.Fatalf("second SendPayloadFragments: %v", err)
	}
	if n1 != 2 || n2 != 2 {
		t.Fatalf("expected 2+2 fragments, got %d+%d", n1, n2)
	}

	p1 := <-recv
	p2 := <-recv
	p3 := <-recv
	p4 := <-recv

	if p2.Seq != p1.Seq+1 || p3.Seq != p2.Seq+1 || p4.Seq != p3.Seq+1 {
		t.Fatalf("non-monotonic sequence: %d %d %d %d", p1.Seq, p2.Seq, p3.Seq, p4.Seq)
	}
}
