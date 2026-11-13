
#ifndef SAMPLEPROTOCOL_COMMON_H
#define SAMPLEPROTOCOL_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>

struct Header_rec {
    __u16 len;
    __u8 flag;
    __u16 body_off; // offset from the start of the application payload
    __u16 body_len;
};

// ---- Telemetry ------------------------------------------------------------------------------
// One event is sent through the perf event array `dsl_events` for every message that was parsed
// completely and passed all filters.  The perf record is
//     [ struct sampleprotocol_event ][ first dsl_snap_len bytes of the packet, starting at the Ethernet header ]
// so the offsets stored in the records (relative to the application payload) can be turned into
// text by the consumer: packet byte = pkt[dsl_app_off + <field>_off].
#define DSL_SNAP_LEN 512

struct sampleprotocol_event {
    __u32 dsl_pkt_len;    // length of the whole packet
    __u32 dsl_snap_len;   // how many packet bytes follow this struct
    __u32 dsl_app_off;    // where the application payload starts inside those bytes
    __u32 dsl_src_ip;     // IPv4 addresses, network byte order
    __u32 dsl_dst_ip;
    __u16 dsl_src_port;   // transport ports, host byte order
    __u16 dsl_dst_port;
    struct Header_rec hdr;
};

#define DSL_EVENT_T struct sampleprotocol_event

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
    printf(" hdr.len=%llu", (unsigned long long)(ev->hdr.len));
    printf(" hdr.flag=%llu", (unsigned long long)(ev->hdr.flag));
    printf(" hdr.body="); dsl_put_bytes(pkt, ev->dsl_snap_len, ev->dsl_app_off + ev->hdr.body_off, ev->hdr.body_len);
}
#endif // DSL_USERSPACE

#endif // SAMPLEPROTOCOL_COMMON_H
