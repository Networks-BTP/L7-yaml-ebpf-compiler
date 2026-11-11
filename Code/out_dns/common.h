
#ifndef DNS_COMMON_H
#define DNS_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>

struct DNSHeader {
    __u16 transaction_id;
    __u16 flags;
    __u16 question_count;
    __u16 answer_count;
    __u16 authority_count;
    __u16 additional_count;
} __attribute__((packed));

// ---- Telemetry ------------------------------------------------------------------------------
// One event is sent through the perf event array `dsl_events` for every message that was parsed
// completely and passed all filters.  The perf record is
//     [ struct dns_event ][ first dsl_snap_len bytes of the packet, starting at the Ethernet header ]
// so the offsets stored in the records (relative to the application payload) can be turned into
// text by the consumer: packet byte = pkt[dsl_app_off + <field>_off].
#define DSL_SNAP_LEN 512

struct dns_event {
    __u32 dsl_pkt_len;    // length of the whole packet
    __u32 dsl_snap_len;   // how many packet bytes follow this struct
    __u32 dsl_app_off;    // where the application payload starts inside those bytes
    __u32 dsl_src_ip;     // IPv4 addresses, network byte order
    __u32 dsl_dst_ip;
    __u16 dsl_src_port;   // transport ports, host byte order
    __u16 dsl_dst_port;
    struct DNSHeader dns_header;
};

#define DSL_EVENT_T struct dns_event

// The event is built on the BPF stack (512 bytes in total).
_Static_assert(sizeof(DSL_EVENT_T) <= 256, "event too large for the BPF stack; reduce the layout or caps");

// Counters in the per-CPU array `dsl_stats` (indices):
#define DSL_STAT_MATCHED  0   // transport + port matched and the segment carries payload
#define DSL_STAT_PARSED   1   // layout parsed completely and every filter passed (an event was sent)
#define DSL_STAT_REJECTED 2   // truncated, over a cap, or marker not found
#define DSL_STAT_FILTERED 3   // parsed, but a filter said no
#define DSL_STAT_COUNT    4

#ifdef DSL_USERSPACE
#include <endian.h>
#include <stdio.h>

static inline void dsl_put_bytes(const unsigned char *pkt, __u32 snap, __u32 off, __u32 len) {
    putchar('"');
    for (__u32 i = 0; i < len; i++) {
        if (off + i >= snap) { fputs("\\\"...(beyond snapshot)", stdout); return; }
        unsigned char c = pkt[off + i];
        if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') putchar(c);
        else printf("\\x%02x", c);
    }
    putchar('"');
}

static inline void dsl_put_hex(const unsigned char *b, __u32 len) {
    for (__u32 i = 0; i < len; i++) printf("%02x", b[i]);
}

// Prints every parsed field of one event as  instance.field=value  (text fields quoted).
static inline void dsl_print_event(const DSL_EVENT_T *ev, const unsigned char *pkt) {
    printf(" dns_header.transaction_id=%llu", (unsigned long long)be16toh(ev->dns_header.transaction_id));
    printf(" dns_header.flags=%llu", (unsigned long long)be16toh(ev->dns_header.flags));
    printf(" dns_header.question_count=%llu", (unsigned long long)be16toh(ev->dns_header.question_count));
    printf(" dns_header.answer_count=%llu", (unsigned long long)be16toh(ev->dns_header.answer_count));
    printf(" dns_header.authority_count=%llu", (unsigned long long)be16toh(ev->dns_header.authority_count));
    printf(" dns_header.additional_count=%llu", (unsigned long long)be16toh(ev->dns_header.additional_count));
}
#endif // DSL_USERSPACE

#endif // DNS_COMMON_H
