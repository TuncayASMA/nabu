package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FrameVersion = 1
	HeaderSize   = 12
	MaxPayload   = 64 * 1024

	FlagData      = 0x01
	FlagConnect   = 0x02
	FlagFIN       = 0x04
	FlagPing      = 0x08 // RTT probe: sender wants a Pong reply
	FlagPong      = 0x10 // RTT probe reply to a Ping
	FlagHandshake = 0x40 // PSK-based session key negotiation
	FlagACK       = 0x80
)

var (
	ErrFrameTooShort     = errors.New("frame too short")
	ErrInvalidVersion    = errors.New("invalid frame version")
	ErrInvalidPayloadLen = errors.New("invalid payload length")
)

// Frame is the wire-level PDU used between client and relay.
type Frame struct {
	Version  byte
	Flags    byte
	StreamID uint16
	Seq      uint32
	Ack      uint32
	Payload  []byte
}

func EncodeFrame(f Frame) ([]byte, error) {
	if f.Version == 0 {
		f.Version = FrameVersion
	}
	if f.Version != FrameVersion {
		return nil, ErrInvalidVersion
	}
	if len(f.Payload) > MaxPayload {
		return nil, ErrInvalidPayloadLen
	}

	buf := make([]byte, HeaderSize+len(f.Payload))
	buf[0] = f.Version
	buf[1] = f.Flags
	binary.BigEndian.PutUint16(buf[2:4], f.StreamID)
	binary.BigEndian.PutUint32(buf[4:8], f.Seq)
	binary.BigEndian.PutUint32(buf[8:12], f.Ack)
	copy(buf[12:], f.Payload)
	return buf, nil
}

func DecodeFrame(raw []byte) (Frame, error) {
	if len(raw) < HeaderSize {
		return Frame{}, ErrFrameTooShort
	}

	version := raw[0]
	if version != FrameVersion {
		return Frame{}, ErrInvalidVersion
	}
	payloadLen := len(raw) - HeaderSize
	if payloadLen > MaxPayload {
		return Frame{}, fmt.Errorf("%w: %d", ErrInvalidPayloadLen, payloadLen)
	}

	payload := make([]byte, payloadLen)
	copy(payload, raw[HeaderSize:])

	return Frame{
		Version:  version,
		Flags:    raw[1],
		StreamID: binary.BigEndian.Uint16(raw[2:4]),
		Seq:      binary.BigEndian.Uint32(raw[4:8]),
		Ack:      binary.BigEndian.Uint32(raw[8:12]),
		Payload:  payload,
	}, nil
}
