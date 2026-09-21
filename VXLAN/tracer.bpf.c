// Required eBPF headers
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "xdp.h"


// XDP Tracer + filtering
SEC("xdp")
int xdp_dns_parser(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // IP filtering ----------- 1
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // UDP filtering ---------- 2
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    // Port filtering (both src & dst) --------- 3 and 4
    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);

    if (sport != 53 && dport != 53)
        return XDP_PASS;

    bpf_printk("dns_tracer: xdp_dns_parser: udp/53 candidate\n");

    // Populate struct nicely (all the required fields)
    // Then check filtering
    // Then send in ring buffer if passes filtering

    struct DNSHeader *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(dns->flags);
    __u8 qr = (flags >> 15) & 0x1;      // Query (0) or Response (1)
    __u8 aa = (flags >> 10) & 0x1;      // Authoritative Answer
    __u8 tc = (flags >> 9) & 0x1;       // Truncated
    __u8 rcode = flags & 0xF;           // Response Code

    if (qr == 0)
        inc_stat(STAT_DNS_QUERIES);
    else
        inc_stat(STAT_DNS_RESPONSES);

    if (tc)
        inc_stat(STAT_TRUNCATED);

    if (rcode == DNS_RCODE_NXDOMAIN)
        inc_stat(STAT_NXDOMAIN);

    struct DNSQueryEvent *event;
    event = bpf_ringbuf_reserve(&dns_events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp = bpf_ktime_get_ns();
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = sport;
    event->dst_port = dport;
    event->query_id = bpf_ntohs(dns->id);
    event->is_response = qr;
    event->rcode = rcode;
    event->answer_count = bpf_ntohs(dns->ancount);
    event->truncated = tc;
    event->authoritative = aa;

    __u8 *dns_ptr = (__u8 *)dns;
    #pragma unroll
    for (int i = 0; i < sizeof(event->raw_payload); i++) {
        if ((void *)(dns_ptr + i + 1) > data_end)
            break;
        event->raw_payload[i] = dns_ptr[i];
    }

    bpf_printk("dns_tracer: xdp_dns_parser: id=%u qr=%u rcode=%u submitted\n",
               event->query_id, qr, rcode);
    bpf_ringbuf_submit(event, 0);

    return XDP_PASS;
}