package tunnel

import (
	"testing"
	"time"
)

func TestWaitForAckSeqMatchesExpected(t *testing.T) {
	ackCh := make(chan uint32, 4)
	ackCh <- 100
	ackCh <- 101
	ackCh <- 102

	if err := waitForAckSeq(ackCh, 101, 100*time.Millisecond); err != nil {
		t.Fatalf("expected matching ack, got error: %v", err)
	}
}

func TestWaitForAckSeqTimeout(t *testing.T) {
	ackCh := make(chan uint32, 1)

	if err := waitForAckSeq(ackCh, 77, 30*time.Millisecond); err == nil {
		t.Fatal("expected timeout error")
	}
}
