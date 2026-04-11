package fec_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/fec"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newDefaultCodec(t *testing.T) *fec.Codec {
	t.Helper()
	c, err := fec.NewCodec(fec.DefaultDataShards, fec.DefaultParityShards)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}

func makePackets(n, size int) [][]byte {
	pkts := make([][]byte, n)
	for i := range pkts {
		pkts[i] = make([]byte, size)
		for j := range pkts[i] {
			pkts[i][j] = byte(i*size+j) & 0xff
		}
	}
	return pkts
}

// ── Codec tests ───────────────────────────────────────────────────────────────

func TestNewCodec_DefaultShards(t *testing.T) {
	c := newDefaultCodec(t)
	if c.DataShards() != fec.DefaultDataShards {
		t.Errorf("DataShards = %d, want %d", c.DataShards(), fec.DefaultDataShards)
	}
	if c.ParityShards() != fec.DefaultParityShards {
		t.Errorf("ParityShards = %d, want %d", c.ParityShards(), fec.DefaultParityShards)
	}
	if c.TotalShards() != fec.DefaultDataShards+fec.DefaultParityShards {
		t.Errorf("TotalShards = %d", c.TotalShards())
	}
}

func TestNewCodec_InvalidShards(t *testing.T) {
	if _, err := fec.NewCodec(0, 3); err == nil {
		t.Error("expected error for dataShards=0")
	}
	if _, err := fec.NewCodec(10, 0); err == nil {
		t.Error("expected error for parityShards=0")
	}
}

func TestReedSolomonEncode10_3(t *testing.T) {
	c := newDefaultCodec(t)
	pkts := makePackets(10, 512)
	frames, err := c.Encode(1, pkts)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(frames) != c.TotalShards() {
		t.Errorf("got %d frames, want %d", len(frames), c.TotalShards())
	}
	for i, f := range frames {
		if len(f) < fec.HeaderSize {
			t.Errorf("frame[%d] too short (%d bytes)", i, len(f))
		}
	}
}

func TestReedSolomonRecoverFrom3Lost(t *testing.T) {
	c := newDefaultCodec(t)
	pkts := makePackets(10, 300)
	frames, err := c.Encode(99, pkts)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Build shards slice (strip headers).
	shards := make([][]byte, c.TotalShards())
	for i, f := range frames {
		shards[i] = f[fec.HeaderSize:]
	}

	// Drop exactly 3 shards (the maximum recoverable).
	shards[0] = nil
	shards[3] = nil
	shards[7] = nil

	recovered, err := c.Reconstruct(shards)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}

	for i, orig := range pkts {
		if !bytes.Equal(orig, recovered[i]) {
			t.Errorf("pkt[%d] mismatch after recovery", i)
		}
	}
}

func TestReedSolomonRecoverMoreThanParityFails(t *testing.T) {
	c := newDefaultCodec(t)
	pkts := makePackets(5, 100)
	frames, err := c.Encode(7, pkts)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	shards := make([][]byte, c.TotalShards())
	for i, f := range frames {
		shards[i] = f[fec.HeaderSize:]
	}
	// Drop 4 shards (> 3 parity) — should fail.
	shards[0] = nil
	shards[1] = nil
	shards[2] = nil
	shards[3] = nil

	if _, err := c.Reconstruct(shards); err == nil {
		t.Error("expected error when too many shards lost")
	}
}

func TestFECOverhead(t *testing.T) {
	// Overhead = parityShards / totalShards ≤ 32%.
	c := newDefaultCodec(t)
	overhead := float64(c.ParityShards()) / float64(c.TotalShards())
	if overhead > 0.32 {
		t.Errorf("FEC overhead %.1f%% exceeds 32%%", overhead*100)
	}
}

func TestHeaderEncodeDecode(t *testing.T) {
	h := fec.FECHeader{GroupID: 0x123456, ShardIdx: 7, NumData: 10}
	buf := make([]byte, fec.HeaderSize)
	h.Encode(buf)
	got := fec.DecodeFECHeader(buf)
	if got != h {
		t.Errorf("round-trip: got %+v, want %+v", got, h)
	}
}

func TestEncodePartialGroup(t *testing.T) {
	// Fewer than DataShards packets — rest should be zero-padded.
	c := newDefaultCodec(t)
	pkts := makePackets(5, 128) // only 5 out of 10
	frames, err := c.Encode(42, pkts)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(frames) != c.TotalShards() {
		t.Errorf("got %d frames", len(frames))
	}
}

func TestEncodeTooManyPackets(t *testing.T) {
	c := newDefaultCodec(t)
	pkts := makePackets(c.DataShards()+1, 64)
	if _, err := c.Encode(0, pkts); err == nil {
		t.Error("expected error for too many packets")
	}
}

func TestReconstructWrongShardCount(t *testing.T) {
	c := newDefaultCodec(t)
	if _, err := c.Reconstruct(make([][]byte, 5)); err == nil {
		t.Error("expected error for wrong shard count")
	}
}

// ── Grouper tests ─────────────────────────────────────────────────────────────

func TestGrouper_FlushOnFull(t *testing.T) {
	c := newDefaultCodec(t)
	g := fec.NewGrouper(c, 0.3)
	defer g.Close()

	// Add exactly DataShards packets — group should flush immediately.
	pkts := makePackets(c.DataShards(), 64)
	for _, p := range pkts {
		g.Add(p)
	}

	select {
	case fg := <-g.Out():
		if len(fg.Frames) != c.TotalShards() {
			t.Errorf("got %d frames, want %d", len(fg.Frames), c.TotalShards())
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no FECGroup received after full group add")
	}
}

func TestGrouper_FlushOnTimeout(t *testing.T) {
	c := newDefaultCodec(t)
	g := fec.NewGrouper(c, 0.3)
	defer g.Close()

	// Add fewer than DataShards — should flush after GroupFlushTimeout.
	g.Add([]byte("hello"))

	select {
	case fg := <-g.Out():
		if len(fg.Frames) != c.TotalShards() {
			t.Errorf("got %d frames, want %d", len(fg.Frames), c.TotalShards())
		}
	case <-time.After(fec.GroupFlushTimeout + 100*time.Millisecond):
		t.Fatal("no FECGroup received after timeout flush")
	}
}

func TestGrouper_ManualFlush(t *testing.T) {
	c := newDefaultCodec(t)
	g := fec.NewGrouper(c, 0.3)
	defer g.Close()

	g.Add([]byte("data1"))
	g.Add([]byte("data2"))
	g.Flush()

	select {
	case fg := <-g.Out():
		if fg.Frames == nil {
			t.Error("nil frames after manual flush")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no FECGroup after Flush()")
	}
}

func TestGrouper_SetRatio(t *testing.T) {
	c := newDefaultCodec(t)
	g := fec.NewGrouper(c, 0)
	g.SetRatio(0.5)
	// Just verify no panic; ratio update confirmed by no error.
	g.Close()
}

func TestGrouper_GroupIDIncrement(t *testing.T) {
	c := newDefaultCodec(t)
	g := fec.NewGrouper(c, 1)
	defer g.Close()

	// Trigger two full groups.
	for i := 0; i < 2*c.DataShards(); i++ {
		g.Add([]byte{byte(i)})
	}

	var ids []uint32
	timeout := time.After(500 * time.Millisecond)
	for len(ids) < 2 {
		select {
		case fg := <-g.Out():
			ids = append(ids, fg.GroupID)
		case <-timeout:
			t.Fatalf("only got %d groups", len(ids))
		}
	}
	if ids[1] != ids[0]+1 {
		t.Errorf("GroupIDs not sequential: %v", ids)
	}
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

func BenchmarkCodecEncode_1KB(b *testing.B) {
	c, _ := fec.NewCodec(fec.DefaultDataShards, fec.DefaultParityShards)
	pkts := makePackets(fec.DefaultDataShards, 1024)
	b.SetBytes(int64(fec.DefaultDataShards * 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Encode(uint32(i), pkts); err != nil { //nolint:gosec
			b.Fatal(err)
		}
	}
}

func BenchmarkCodecEncode_64KB(b *testing.B) {
	c, _ := fec.NewCodec(fec.DefaultDataShards, fec.DefaultParityShards)
	pkts := makePackets(fec.DefaultDataShards, 64*1024)
	b.SetBytes(int64(fec.DefaultDataShards * 64 * 1024))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Encode(uint32(i), pkts); err != nil { //nolint:gosec
			b.Fatal(err)
		}
	}
}
