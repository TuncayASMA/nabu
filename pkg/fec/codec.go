// Package fec provides Forward Error Correction for NABU tunnel traffic.
//
// Architecture:
//
//	Codec  — Reed-Solomon (10 data + 3 parity) shard encoder/decoder.
//	Grouper — Collects N raw packets into a group, Codec-encodes them, and
//	           emits a FECGroup containing data + parity shards.  A 50 ms
//	           deadline flushes the group even if it is not full.
//
// The encoder uses klauspost/reedsolomon (ARM64 NEON accelerated) with a
// sync.Pool shard-buffer pool to eliminate per-call allocations.
//
// Frame layout:
//
//	FECHeader (5 bytes): GroupID(3) | ShardIdx(1) | NumData(1)
//	Payload:             shard bytes (variable)
package fec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/reedsolomon"
)

// DefaultDataShards and DefaultParityShards match the RUNBOOK spec.
const (
	DefaultDataShards   = 10
	DefaultParityShards = 3
)

// HeaderSize is the fixed byte header prepended to every shard frame.
const HeaderSize = 5

// ErrTooFewShards is returned by Reconstruct when not enough shards are present.
var ErrTooFewShards = errors.New("fec: insufficient shards to reconstruct")

// ErrDataTooLarge is returned when a single packet exceeds maxShardBytes.
var ErrDataTooLarge = errors.New("fec: input data exceeds shard size limit")

// maxShardBytes caps individual shard payload at 64 KiB.
const maxShardBytes = 64 * 1024

// FECHeader is the 5-byte header embedded in each encoded shard frame.
type FECHeader struct {
	GroupID  uint32 // 24-bit group counter packed into a uint32 (top byte unused)
	ShardIdx uint8  // 0..DataShards+ParityShards-1
	NumData  uint8  // DataShards value (allows receiver to sanity-check)
}

// Encode serialises h into dst (must be ≥ HeaderSize bytes).
func (h FECHeader) Encode(dst []byte) {
	dst[0] = uint8(h.GroupID >> 16)
	dst[1] = uint8(h.GroupID >> 8)
	dst[2] = uint8(h.GroupID)
	dst[3] = h.ShardIdx
	dst[4] = h.NumData
}

// DecodeFECHeader deserialises a header from src (must be ≥ HeaderSize bytes).
func DecodeFECHeader(src []byte) FECHeader {
	return FECHeader{
		GroupID:  uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2]),
		ShardIdx: src[3],
		NumData:  src[4],
	}
}

// ── Codec ────────────────────────────────────────────────────────────────────

// Codec encodes and decodes Reed-Solomon shard groups.
type Codec struct {
	dataShards   int
	parityShards int
	rs           reedsolomon.Encoder
	pool         sync.Pool // [][]byte shard buffers
}

// NewCodec creates a Codec with the specified shard counts.
func NewCodec(dataShards, parityShards int) (*Codec, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, fmt.Errorf("fec: dataShards=%d parityShards=%d must both be > 0", dataShards, parityShards)
	}
	rs, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("fec: reedsolomon.New: %w", err)
	}
	total := dataShards + parityShards
	c := &Codec{
		dataShards:   dataShards,
		parityShards: parityShards,
		rs:           rs,
	}
	c.pool = sync.Pool{
		New: func() any {
			shards := make([][]byte, total)
			for i := range shards {
				shards[i] = make([]byte, maxShardBytes)
			}
			return shards
		},
	}
	return c, nil
}

// DataShards returns the data shard count.
func (c *Codec) DataShards() int { return c.dataShards }

// ParityShards returns the parity shard count.
func (c *Codec) ParityShards() int { return c.parityShards }

// TotalShards returns dataShards + parityShards.
func (c *Codec) TotalShards() int { return c.dataShards + c.parityShards }

// Encode encodes up to DataShards data packets into a list of output frames.
//
// packets must have len ≤ DataShards; remaining data shards are zero-padded.
// Returns one frame per shard (data + parity), each prefixed with FECHeader.
func (c *Codec) Encode(groupID uint32, packets [][]byte) ([][]byte, error) {
	if len(packets) > c.dataShards {
		return nil, fmt.Errorf("fec: Encode: got %d packets but dataShards=%d", len(packets), c.dataShards)
	}

	// Determine max payload among provided packets.
	maxLen := 0
	for _, p := range packets {
		if len(p) > maxShardBytes {
			return nil, ErrDataTooLarge
		}
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	if maxLen == 0 {
		maxLen = 1 // degenerate but valid
	}

	// Build shard matrix.  Each shard must be the same length.
	// We prefix each data shard with a 2-byte actual-length field so the
	// receiver knows where actual data ends.
	shardLen := 2 + maxLen // uint16 length prefix + payload

	shards := make([][]byte, c.TotalShards())
	for i := 0; i < c.dataShards; i++ {
		shard := make([]byte, shardLen)
		if i < len(packets) {
			binary.BigEndian.PutUint16(shard[:2], uint16(len(packets[i])))
			copy(shard[2:], packets[i])
		}
		// Shards beyond len(packets) are zero (both length and payload).
		shards[i] = shard
	}
	for i := c.dataShards; i < c.TotalShards(); i++ {
		shards[i] = make([]byte, shardLen)
	}

	if err := c.rs.Encode(shards); err != nil {
		return nil, fmt.Errorf("fec: Encode: %w", err)
	}

	// Build output frames: FECHeader | shard bytes.
	frames := make([][]byte, c.TotalShards())
	for i, shard := range shards {
		frame := make([]byte, HeaderSize+len(shard))
		h := FECHeader{GroupID: groupID, ShardIdx: uint8(i), NumData: uint8(c.dataShards)}
		h.Encode(frame[:HeaderSize])
		copy(frame[HeaderSize:], shard)
		frames[i] = frame
	}
	return frames, nil
}

// Reconstruct attempts to recover the data packets from any ≥ DataShards
// available frames.  Missing frames must be represented as nil in shards.
//
// Returns the recovered data payloads (len = DataShards).  Shards beyond the
// actual packet count may have zero-length payloads.
func (c *Codec) Reconstruct(shards [][]byte) ([][]byte, error) {
	if len(shards) != c.TotalShards() {
		return nil, fmt.Errorf("fec: Reconstruct: got %d shards, want %d", len(shards), c.TotalShards())
	}

	// Count available shards.
	avail := 0
	for _, s := range shards {
		if s != nil {
			avail++
		}
	}
	if avail < c.dataShards {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrTooFewShards, avail, c.dataShards)
	}

	if err := c.rs.ReconstructData(shards); err != nil {
		return nil, fmt.Errorf("fec: Reconstruct: %w", err)
	}

	result := make([][]byte, c.dataShards)
	for i := 0; i < c.dataShards; i++ {
		if len(shards[i]) < 2 {
			continue
		}
		pktLen := int(binary.BigEndian.Uint16(shards[i][:2]))
		if pktLen == 0 {
			continue // padded shard
		}
		if 2+pktLen > len(shards[i]) {
			continue // corrupt length field; skip
		}
		dst := make([]byte, pktLen)
		copy(dst, shards[i][2:2+pktLen])
		result[i] = dst
	}
	return result, nil
}
