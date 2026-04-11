// SPDX-License-Identifier: GPL-2.0
/*
 * nabu_monitor.c — NABU eBPF traffic monitor
 *
 * Attaches a TC (traffic control) clsact hook on ingress and egress of a
 * network interface. For each packet it:
 *   1. Increments per-direction packet/byte counters (BPF_MAP_TYPE_ARRAY).
 *   2. Computes an inter-arrival time (IAT) using a per-CPU timestamp and
 *      pushes the IAT value into a BPF ring buffer for user-space consumption.
 *
 * Build:
 *   clang -O2 -target bpf -D__TARGET_ARCH_arm64 \
 *         -I/usr/include/aarch64-linux-gnu \
 *         -c nabu_monitor.c -o nabu_monitor.bpf.o
 *
 *   (Or use `go generate ./pkg/governor/ebpf/` which invokes bpf2go.)
 *
 * CO-RE:  compiled with libbpf / BTF; no kernel header pinning required
 *         at runtime.
 */

#include "vmlinux.h"               /* BTF-generated kernel types (bpf2go) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define NABU_DIR_INGRESS  0
#define NABU_DIR_EGRESS   1
#define NABU_DIR_MAX      2

/* Ring buffer capacity: 4 MiB (must be multiple of page size). */
#define NABU_RB_SIZE      (4 << 20)

/* -------------------------------------------------------------------------
 * BPF Maps
 * ---------------------------------------------------------------------- */

/* Per-direction packet and byte counters. */
struct nabu_counter {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NABU_DIR_MAX);
    __type(key, __u32);
    __type(value, struct nabu_counter);
} nabu_counters SEC(".maps");

/* Per-CPU last-seen timestamp for IAT computation. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NABU_DIR_MAX);
    __type(key, __u32);
    __type(value, __u64);
} nabu_last_ts SEC(".maps");

/* Ring buffer for user-space IAT event stream. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, NABU_RB_SIZE);
} nabu_events SEC(".maps");

/* -------------------------------------------------------------------------
 * Event structure pushed to ring buffer
 * ---------------------------------------------------------------------- */

struct nabu_event {
    __u64 ts_ns;       /* absolute timestamp (bpf_ktime_get_ns) */
    __u64 iat_ns;      /* inter-arrival time; 0 for first packet */
    __u32 pkt_len;     /* packet length in bytes */
    __u8  direction;   /* NABU_DIR_INGRESS or NABU_DIR_EGRESS */
    __u8  pad[3];
};

/* -------------------------------------------------------------------------
 * Shared processing logic
 * ---------------------------------------------------------------------- */

static __always_inline int nabu_process(struct __sk_buff *skb, __u8 dir)
{
    __u32 key = dir;
    __u64 now = bpf_ktime_get_ns();
    __u32 pkt_len = skb->len;

    /* Update counters. */
    struct nabu_counter *cnt = bpf_map_lookup_elem(&nabu_counters, &key);
    if (cnt) {
        __sync_fetch_and_add(&cnt->packets, 1);
        __sync_fetch_and_add(&cnt->bytes, pkt_len);
    }

    /* Compute IAT from per-CPU last timestamp. */
    __u64 *last = bpf_map_lookup_elem(&nabu_last_ts, &key);
    __u64 iat = 0;
    if (last && *last != 0)
        iat = now - *last;
    if (last)
        *last = now;

    /* Push event to ring buffer (best-effort: drop if full). */
    struct nabu_event *ev = bpf_ringbuf_reserve(&nabu_events,
                                                sizeof(*ev), 0);
    if (ev) {
        ev->ts_ns     = now;
        ev->iat_ns    = iat;
        ev->pkt_len   = pkt_len;
        ev->direction = dir;
        __builtin_memset(ev->pad, 0, sizeof(ev->pad));
        bpf_ringbuf_submit(ev, 0);
    }

    return TC_ACT_OK;
}

/* -------------------------------------------------------------------------
 * TC hook programs
 * ---------------------------------------------------------------------- */

SEC("tc/ingress")
int nabu_ingress(struct __sk_buff *skb)
{
    return nabu_process(skb, NABU_DIR_INGRESS);
}

SEC("tc/egress")
int nabu_egress(struct __sk_buff *skb)
{
    return nabu_process(skb, NABU_DIR_EGRESS);
}

char __license[] SEC("license") = "GPL";
