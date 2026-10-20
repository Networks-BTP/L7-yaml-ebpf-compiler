
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

SEC("xdp")
int xdp_crossproto_parser(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
    struct tcphdr *l4 = (void *)ip + ip_hdr_len;
    if ((void *)(l4 + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(l4->dest) != 7001 && bpf_ntohs(l4->source) != 7001) return XDP_PASS;
    void *app_payload = (void *)l4 + (l4->doff * 4);

    // 3. Application Protocol Layout Parsing
    void *cursor = app_payload;

    // Parse Layout Instance: hdr (Type: Header)
    struct Header *hdr = cursor;
    if ((void *)(hdr + 1) > data_end) return XDP_PASS;
    cursor = (void *)(hdr + 1);

    // Parse Layout Instance: a (Type: Chunk)
    struct Chunk_rec a = {};
    // a.data: length-prefixed, size = hdr.len_a * 1 + (0), at most 16 byte(s)
    {
        __s64 n = (__s64)hdr->len_a * 1 + (0);
        if (n < 0 || n > 16) return XDP_PASS;
        if ((__u8 *)cursor + n > (__u8 *)data_end) return XDP_PASS;
        a.data_off = (__u16)((__u8 *)cursor - (__u8 *)app_payload);
        a.data_len = (__u16)n;
        cursor = (__u8 *)cursor + n;
    }
    // a: fixed run of 1 byte(s)
    if ((__u8 *)cursor + 1 > (__u8 *)data_end) return XDP_PASS;
    a.tail = DSL_LOAD(__u8, (__u8 *)cursor + 0);
    cursor = (__u8 *)cursor + 1;

    // Parse Layout Instance: b (Type: Chunk)
    struct Chunk_rec b = {};
    // b.data: length-prefixed, size = hdr.len_b * 2 + (0), at most 32 byte(s)
    {
        __s64 n = (__s64)hdr->len_b * 2 + (0);
        if (n < 0 || n > 32) return XDP_PASS;
        if ((__u8 *)cursor + n > (__u8 *)data_end) return XDP_PASS;
        b.data_off = (__u16)((__u8 *)cursor - (__u8 *)app_payload);
        b.data_len = (__u16)n;
        cursor = (__u8 *)cursor + n;
    }
    // b: fixed run of 1 byte(s)
    if ((__u8 *)cursor + 1 > (__u8 *)data_end) return XDP_PASS;
    b.tail = DSL_LOAD(__u8, (__u8 *)cursor + 0);
    cursor = (__u8 *)cursor + 1;

    // Parse Layout Instance: c (Type: Chunk)
    struct Chunk_rec c = {};
    // c.data: length-prefixed, size = a.tail * 1 + (0), at most 8 byte(s)
    {
        __s64 n = (__s64)a.tail * 1 + (0);
        if (n < 0 || n > 8) return XDP_PASS;
        if ((__u8 *)cursor + n > (__u8 *)data_end) return XDP_PASS;
        c.data_off = (__u16)((__u8 *)cursor - (__u8 *)app_payload);
        c.data_len = (__u16)n;
        cursor = (__u8 *)cursor + n;
    }
    // c: fixed run of 1 byte(s)
    if ((__u8 *)cursor + 1 > (__u8 *)data_end) return XDP_PASS;
    c.tail = DSL_LOAD(__u8, (__u8 *)cursor + 0);
    cursor = (__u8 *)cursor + 1;


    // 4. Observability Filters
    if (!(bpf_ntohs(hdr->magic) == 51966ULL)) return XDP_PASS;

    // Payload successfully parsed and matched!
    // (Telemetry emission / Ringbuf logic would go here)

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
