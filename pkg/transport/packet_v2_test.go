package transport

import (
	"bytes"
	"testing"
)

func TestPacketEncodeDecodeRoundTrip(t *testing.T) {
	in := Packet{
		Seq:       42,
		Flags:     PacketFlagData,
		Timestamp: 123456789,
		Payload:   []byte("hello-udp-transport"),
	}

	raw, err := EncodePacket(in)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}

	out, err := DecodePacket(raw)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}

	if out.Seq != in.Seq || out.Flags != in.Flags || out.Timestamp != in.Timestamp {
		t.Fatalf("header mismatch: got=%+v want=%+v", out, in)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch: got=%q want=%q", out.Payload, in.Payload)
	}
}

func TestPacketCRCDetectsCorruption(t *testing.T) {
	raw, err := EncodePacket(Packet{Seq: 1, Flags: PacketFlagData, Timestamp: 1, Payload: []byte("abc")})
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF

	if _, err := DecodePacket(raw); err == nil {
		t.Fatal("expected crc mismatch error")
	}
}

func TestMTUSafetyFragmentation(t *testing.T) {
	payload := make([]byte, MaxUDPPayload+400)
	chunks := FragmentPayload(payload, MaxUDPPayload)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c) > MaxUDPPayload {
			t.Fatalf("chunk[%d] exceeds mtu-safe payload: %d", i, len(c))
		}
	}

	recombined := append(chunks[0], chunks[1]...)
	if len(recombined) != len(payload) {
		t.Fatalf("recombined len mismatch: got=%d want=%d", len(recombined), len(payload))
	}
}
