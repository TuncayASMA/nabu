package transport

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

const (
	// PacketHeaderSize = 2B seq + 1B flags + 4B timestamp.
	PacketHeaderSize = 7
	// PacketCRCSize is trailing CRC32 (IEEE) size.
	PacketCRCSize = 4
	// MaxUDPPayload keeps UDP frames MTU-safe in typical internet paths.
	MaxUDPPayload = 1350
)

const (
	PacketFlagData      byte = 0x01
	PacketFlagACK       byte = 0x02
	PacketFlagFIN       byte = 0x04
	PacketFlagKeepalive byte = 0x08
)

var (
	ErrPacketTooShort    = errors.New("packet too short")
	ErrPacketTooLarge    = errors.New("packet payload too large")
	ErrPacketCRCMismatch = errors.New("packet crc mismatch")
)

// Packet is the v2 UDP transport datagram format.
// Wire: [2B seq][1B flags][4B timestamp][payload][4B crc32].
type Packet struct {
	Seq       uint16
	Flags     byte
	Timestamp uint32
	Payload   []byte
}

func EncodePacket(p Packet) ([]byte, error) {
	if len(p.Payload) > MaxUDPPayload {
		return nil, ErrPacketTooLarge
	}

	total := PacketHeaderSize + len(p.Payload) + PacketCRCSize
	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], p.Seq)
	buf[2] = p.Flags
	binary.BigEndian.PutUint32(buf[3:7], p.Timestamp)
	copy(buf[7:7+len(p.Payload)], p.Payload)

	crc := crc32.ChecksumIEEE(buf[:total-PacketCRCSize])
	binary.BigEndian.PutUint32(buf[total-PacketCRCSize:], crc)
	return buf, nil
}

func DecodePacket(raw []byte) (Packet, error) {
	if len(raw) < PacketHeaderSize+PacketCRCSize {
		return Packet{}, ErrPacketTooShort
	}

	gotCRC := binary.BigEndian.Uint32(raw[len(raw)-PacketCRCSize:])
	wantCRC := crc32.ChecksumIEEE(raw[:len(raw)-PacketCRCSize])
	if gotCRC != wantCRC {
		return Packet{}, ErrPacketCRCMismatch
	}

	payload := raw[PacketHeaderSize : len(raw)-PacketCRCSize]
	if len(payload) > MaxUDPPayload {
		return Packet{}, ErrPacketTooLarge
	}

	out := Packet{
		Seq:       binary.BigEndian.Uint16(raw[0:2]),
		Flags:     raw[2],
		Timestamp: binary.BigEndian.Uint32(raw[3:7]),
		Payload:   make([]byte, len(payload)),
	}
	copy(out.Payload, payload)
	return out, nil
}

// FragmentPayload splits payload into mtu-safe chunks.
func FragmentPayload(payload []byte, maxChunk int) [][]byte {
	if maxChunk <= 0 {
		maxChunk = MaxUDPPayload
	}
	if len(payload) <= maxChunk {
		one := make([]byte, len(payload))
		copy(one, payload)
		return [][]byte{one}
	}

	count := (len(payload) + maxChunk - 1) / maxChunk
	out := make([][]byte, 0, count)
	for start := 0; start < len(payload); start += maxChunk {
		end := start + maxChunk
		if end > len(payload) {
			end = len(payload)
		}
		chunk := make([]byte, end-start)
		copy(chunk, payload[start:end])
		out = append(out, chunk)
	}
	return out
}
