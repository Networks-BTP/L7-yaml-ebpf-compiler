
#include "common.h"
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Unaligned-safe load of a fixed-size value from packet memory.
#define DSL_LOAD(type, p) ({ type _v; __builtin_memcpy(&_v, (p), sizeof(_v)); _v; })

// Emits no instruction, but stops the compiler from seeing through `x`.
#define DSL_OPAQUE(x) __asm__ __volatile__("" : "+r"(x))

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} dsl_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DSL_STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} dsl_stats SEC(".maps");

static __always_inline void dsl_count(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&dsl_stats, &idx);
    if (v) (*v)++;
}

// A message that cannot be parsed (truncated, over a cap, marker missing): count it, let the packet pass.
#define DSL_REJECT do { dsl_count(DSL_STAT_REJECTED); return XDP_PASS; } while (0)

SEC("xdp")
int xdp_sampleprotocol_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. L2/L3 Parsing
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 2. L4 Transport Check
    int ip_hdr_len = ip->ihl * 4;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *l4 = (void *)ip + ip_hdr_len;
    if ((void *)(l4 + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(l4->dest) != 9999 && bpf_ntohs(l4->source) != 9999) return XDP_PASS;
    void *app_payload = (void *)(l4 + 1);

    if ((__u8 *)app_payload >= (__u8 *)data_end) return XDP_PASS;   // no payload (e.g. a bare ACK)
    dsl_count(DSL_STAT_MATCHED);

    // 3. Application Protocol Layout Parsing
    void *cursor = app_payload;

    // Parse Layout Instance: hdr (Type: Header)
    struct Header_rec hdr = {};
    // hdr: fixed run of 3 byte(s)
    if ((__u8 *)cursor + 3 > (__u8 *)data_end) DSL_REJECT;
    hdr.len = bpf_ntohs(DSL_LOAD(__u16, (__u8 *)cursor + 0));
    hdr.flag = DSL_LOAD(__u8, (__u8 *)cursor + 2);
    cursor = (__u8 *)cursor + 3;
    // hdr.body: length-prefixed, size = hdr.len * 1 + (0), at most 1024 byte(s)
    {
        __s64 n = (__s64)hdr.len * 1 + (0);
        if (n < 0 || n > 1024) DSL_REJECT;
        if ((__u8 *)cursor + n > (__u8 *)data_end) DSL_REJECT;
        hdr.body_off = (__u16)((__u8 *)cursor - (__u8 *)app_payload);
        hdr.body_len = (__u16)n;
        cursor = (__u8 *)cursor + n;
    }


    // 4. Observability Filters
    if (!(hdr.flag == 1ULL)) { dsl_count(DSL_STAT_FILTERED); return XDP_DROP; }
    // Payload successfully parsed and matched!
    {
        DSL_EVENT_T ev = {};
        __u32 pkt_len = (__u32)((__u8 *)data_end - (__u8 *)data);
        __u32 snap = pkt_len < DSL_SNAP_LEN ? pkt_len : DSL_SNAP_LEN;
        ev.dsl_pkt_len = pkt_len;
        ev.dsl_snap_len = snap;
        ev.dsl_app_off = (__u32)((__u8 *)app_payload - (__u8 *)data);
        ev.dsl_src_ip = ip->saddr;
        ev.dsl_dst_ip = ip->daddr;
        ev.dsl_src_port = bpf_ntohs(l4->source);
        ev.dsl_dst_port = bpf_ntohs(l4->dest);
        ev.hdr = hdr;
        dsl_count(DSL_STAT_PARSED);
        // The upper 32 bits of the flags ask the kernel to append that many packet bytes to the record.
        bpf_perf_event_output(ctx, &dsl_events, BPF_F_CURRENT_CPU | ((__u64)snap << 32), &ev, sizeof(ev));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
