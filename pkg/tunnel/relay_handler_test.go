package tunnel

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

type relayErrLayer struct {
	recvErr error
}

func (l *relayErrLayer) SendFrame(transport.Frame) error {
	return nil
}

func (l *relayErrLayer) ReceiveFrame() (transport.Frame, error) {
	return transport.Frame{}, l.recvErr
}

func (l *relayErrLayer) Close() error {
	return nil
}

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

func TestWaitForAckSeqClosedChannel(t *testing.T) {
	ackCh := make(chan uint32)
	close(ackCh)

	start := time.Now()
	err := waitForAckSeq(ackCh, 55, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected closed channel error")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected fast return on closed channel, got %s", elapsed)
	}
}

func TestPipeRelayToConnClosesAckChannelOnReceiveError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ackCh := make(chan uint32, 1)
	shutdownCh := make(chan error, 1)

	l := &relayErrLayer{recvErr: errors.New("boom")}
	go pipeRelayToConn(clientConn, l, 1, ackCh, func(err error) {
		shutdownCh <- err
	})

	select {
	case _, ok := <-ackCh:
		if ok {
			t.Fatal("expected ack channel to be closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected ack channel to close promptly")
	}

	select {
	case err := <-shutdownCh:
		if err == nil {
			t.Fatal("expected shutdown error")
		}
		if !strings.Contains(err.Error(), "receive relay frame failed") {
			t.Fatalf("unexpected shutdown error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected shutdown callback")
	}
}

func TestTryEnqueueACK(t *testing.T) {
	ackCh := make(chan uint32, 1)
	if ok := tryEnqueueACK(ackCh, 10); !ok {
		t.Fatal("expected first enqueue to succeed")
	}
	if got := <-ackCh; got != 10 {
		t.Fatalf("unexpected ack value: got=%d want=10", got)
	}
}

func TestTryEnqueueACKFullChannel(t *testing.T) {
	ackCh := make(chan uint32, 1)
	ackCh <- 77

	start := time.Now()
	ok := tryEnqueueACK(ackCh, 88)
	if ok {
		t.Fatal("expected enqueue to fail when channel is full")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected non-blocking fast return, got %s", elapsed)
	}
	if got := <-ackCh; got != 77 {
		t.Fatalf("expected original ack to remain, got=%d", got)
	}
}

func TestDroppedACKCountIncrements(t *testing.T) {
	start := DroppedACKCount()
	ackCh := make(chan uint32, 1)
	ackCh <- 1

	if ok := tryEnqueueACK(ackCh, 2); ok {
		t.Fatal("expected enqueue to fail on full channel")
	}

	if got := DroppedACKCount(); got != start+1 {
		t.Fatalf("unexpected dropped ack count: got=%d want=%d", got, start+1)
	}
}
