
#include "common.h"
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_toyproto_parser(struct xdp_md *ctx) {
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

    // 3. Application Protocol Layout Parsing
    void *cursor = app_payload;

    // Parse Layout Instance: hdr (Type: Header)
    struct Header *hdr = cursor;
    if ((void *)(hdr + 1) > data_end) return XDP_PASS;
    cursor = (void *)(hdr + 1);

    // Parse Layout Instance: body (Type: Body)
    struct Body *body = cursor;
    if ((void *)(body + 1) > data_end) return XDP_PASS;
    cursor = (void *)(body + 1);


    // 4. Observability Filters
    if (!((hdr->opcode) == 1ULL)) return XDP_PASS;
    if (!((hdr->version) > 0ULL)) return XDP_PASS;

    // Payload successfully parsed and matched!
    // (Telemetry emission / Ringbuf logic would go here)
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
