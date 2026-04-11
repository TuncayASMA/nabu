//go:build ignore
// +build ignore

// impl_linux_real.go — real eBPF backend using bpf2go-generated types.
//
// This file is excluded from normal builds (go:build ignore).
// It will be enabled once bpf2go generates nabu_monitor_bpfeb.go /
// nabu_monitor_bpfel.go after running:
//
//	go generate ./pkg/governor/ebpf/
//
// To activate:
//  1. Install clang and run go generate.
//  2. Remove the `//go:build ignore` line from this file.
//  3. Remove impl_stub.go (or gate it with `//go:build !linux`).
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// realImpl is the live eBPF backend (Linux only).
type realImpl struct {
	objs   nabuMonitorObjects
	tcIngr link.Link
	tcEgr  link.Link
	rd     *ringbuf.Reader
}

func newImpl() monitorImpl { return &realImpl{} }

func (r *realImpl) attach(iface string) error {
	// Allow the current process to lock memory for eBPF maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	if err := loadNabuMonitorObjects(&r.objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}

	// Look up the network interface.
	ifaceObj, err := netInterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", iface, err)
	}

	// Attach TC clsact hooks.
	r.tcIngr, err = link.AttachTCX(link.TCXOptions{
		Interface: ifaceObj.Index,
		Program:   r.objs.NabuIngress,
		Attach:    ciliumebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach ingress: %w", err)
	}

	r.tcEgr, err = link.AttachTCX(link.TCXOptions{
		Interface: ifaceObj.Index,
		Program:   r.objs.NabuEgress,
		Attach:    ciliumebpf.AttachTCXEgress,
	})
	if err != nil {
		r.tcIngr.Close() //nolint:errcheck
		return fmt.Errorf("attach egress: %w", err)
	}

	r.rd, err = ringbuf.NewReader(r.objs.NabuEvents)
	if err != nil {
		r.tcIngr.Close() //nolint:errcheck
		r.tcEgr.Close()  //nolint:errcheck
		return fmt.Errorf("ringbuf reader: %w", err)
	}

	return nil
}

func (r *realImpl) readEvents(ctx context.Context, ch chan<- Event) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := r.rd.Read()
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			return
		}

		var raw struct {
			TsNs      uint64
			IatNs     uint64
			PktLen    uint32
			Direction uint8
			Pad       [3]uint8
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		ev := Event{
			TimestampNS: raw.TsNs,
			IATNS:       raw.IatNs,
			PktLen:      raw.PktLen,
			Direction:   Direction(raw.Direction),
		}

		select {
		case ch <- ev:
		default: // drop if consumer is slow
		}
	}
}

func (r *realImpl) counters() (Counter, Counter, error) {
	var ingress, egress nabuMonitorNabuCounter
	key := uint32(0)
	if err := r.objs.NabuCounters.Lookup(&key, &ingress); err != nil {
		return Counter{}, Counter{}, err
	}
	key = 1
	if err := r.objs.NabuCounters.Lookup(&key, &egress); err != nil {
		return Counter{}, Counter{}, err
	}
	return Counter{Packets: ingress.Packets, Bytes: ingress.Bytes},
		Counter{Packets: egress.Packets, Bytes: egress.Bytes},
		nil
}

func (r *realImpl) close() error {
	if r.rd != nil {
		r.rd.Close() //nolint:errcheck
	}
	if r.tcIngr != nil {
		r.tcIngr.Close() //nolint:errcheck
	}
	if r.tcEgr != nil {
		r.tcEgr.Close() //nolint:errcheck
	}
	return r.objs.Close()
}

// netInterfaceByName is a thin wrapper over net.InterfaceByName for testability.
func netInterfaceByName(name string) (*netIface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return &netIface{Index: iface.Index}, nil
}

type netIface struct{ Index int }
