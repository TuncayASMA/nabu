package transport

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameEncodeDecodeRoundTrip(t *testing.T) {
	in := Frame{
		Version:  FrameVersion,
		Flags:    0x03,
		StreamID: 42,
		Seq:      100,
		Ack:      90,
		Payload:  []byte("hello transport"),
	}

	raw, err := EncodeFrame(in)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	out, err := DecodeFrame(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if out.Version != in.Version || out.Flags != in.Flags || out.StreamID != in.StreamID || out.Seq != in.Seq || out.Ack != in.Ack {
		t.Fatalf("header mismatch: in=%+v out=%+v", in, out)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch: got=%q want=%q", string(out.Payload), string(in.Payload))
	}
}

func TestDecodeRejectsShortFrame(t *testing.T) {
	_, err := DecodeFrame([]byte{1, 2, 3})
	if !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("expected short frame error, got=%v", err)
	}
}

func TestDecodeRejectsVersion(t *testing.T) {
	raw := make([]byte, HeaderSize)
	raw[0] = 9
	_, err := DecodeFrame(raw)
	if !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("expected invalid version error, got=%v", err)
	}
}

func TestEncodeRejectsTooLargePayload(t *testing.T) {
	p := make([]byte, MaxPayload+1)
	_, err := EncodeFrame(Frame{Version: FrameVersion, Payload: p})
	if !errors.Is(err, ErrInvalidPayloadLen) {
		t.Fatalf("expected payload len error, got=%v", err)
	}
}

func TestDecodeAcceptsMaxPayload(t *testing.T) {
	p := make([]byte, MaxPayload)
	raw, err := EncodeFrame(Frame{Version: FrameVersion, Payload: p})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	out, err := DecodeFrame(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(out.Payload) != MaxPayload {
		t.Fatalf("unexpected payload len: %d", len(out.Payload))
	}
}

func TestDecodeRejectsOversizedPayload(t *testing.T) {
	raw := make([]byte, HeaderSize+MaxPayload+1)
	raw[0] = FrameVersion
	_, err := DecodeFrame(raw)
	if !errors.Is(err, ErrInvalidPayloadLen) {
		t.Fatalf("expected invalid payload len error, got=%v", err)
	}
}

func TestFrameEncodeDecodeControlFlags(t *testing.T) {
	tests := []byte{FlagConnect, FlagFIN}

	for _, flags := range tests {
		raw, err := EncodeFrame(Frame{Version: FrameVersion, Flags: flags, StreamID: 9, Seq: 3, Ack: 2, Payload: []byte("x")})
		if err != nil {
			t.Fatalf("encode failed for flags=%d: %v", flags, err)
		}

		out, err := DecodeFrame(raw)
		if err != nil {
			t.Fatalf("decode failed for flags=%d: %v", flags, err)
		}
		if out.Flags != flags {
			t.Fatalf("unexpected flags: got=%d want=%d", out.Flags, flags)
		}
	}
}
