
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

// Count packets that pass all protocol-specific filters.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} match_count SEC(".maps");

SEC("xdp")
int xdp_dns_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. L2/L3 Parsing
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 2. Validate IPv4 boundaries.
    __u8 ihl = ip->ihl;
if (ihl < 5 || ihl > 15) return XDP_PASS;

// Prove the maximum IPv4 header fits before variable pointer arithmetic.
if ((__u8 *)ip + 60 > (__u8 *)data_end) return XDP_PASS;

__u32 ip_hdr_len = (__u32)ihl * 4;

    __u16 ip_total_len = bpf_ntohs(ip->tot_len);
    if (ip_total_len < ip_hdr_len) return XDP_PASS;
    void *ip_end = (void *)ip + ip_total_len;
    if (ip_end > data_end) return XDP_PASS;

    // Only parse complete, unfragmented IPv4 packets.
    if (bpf_ntohs(ip->frag_off) & 0x3FFF) return XDP_PASS;

    // 3. Validate transport header and establish payload boundary.
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *l4 = (void *)ip + ip_hdr_len;
    if ((void *)(l4 + 1) > ip_end) return XDP_PASS;
    __u16 udp_len = bpf_ntohs(l4->len);
    if (udp_len < sizeof(*l4)) return XDP_PASS;
    if (udp_len > ip_total_len - ip_hdr_len) return XDP_PASS;
    if (bpf_ntohs(l4->dest) != 53 && bpf_ntohs(l4->source) != 53) return XDP_PASS;
    void *app_payload = (void *)(l4 + 1);
    void *payload_end = (void *)l4 + udp_len;

    // 3. Application Protocol Layout Parsing
    void *cursor = app_payload;

    // Parse Layout Instance: dns_header (Type: DNSHeader)
    struct DNSHeader *dns_header = cursor;
    if ((void *)(dns_header + 1) > payload_end) return XDP_PASS;
    cursor = (void *)(dns_header + 1);


    // 4. Observability Filters
    if (!(bpf_ntohs(dns_header->question_count) > 0ULL)) return XDP_PASS;

    // Payload successfully parsed and matched: increment this CPU's counter.
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&match_count, &key);
    if (count)
        (*count)++;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
