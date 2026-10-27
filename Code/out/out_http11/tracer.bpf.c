
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

SEC("xdp")
int xdp_http11_parser(struct xdp_md *ctx) {
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
    if (bpf_ntohs(l4->dest) != 8080 && bpf_ntohs(l4->source) != 8080) return XDP_PASS;
    void *app_payload = (void *)l4 + (l4->doff * 4);

    // 3. Application Protocol Layout Parsing
    void *cursor = app_payload;

    // Parse Layout Instance: req (Type: Request)
    struct Request_rec req = {};
    // req.method: delimiter " ", value at most 8 byte(s)
    {
        __u32 off0 = ((__u32)((__u8 *)cursor - (__u8 *)app_payload)) & 0x3FFF;
        __u32 n = 0, alive = 1;
        #pragma unroll
        for (int i = 0; i <= 8; i++) {
            __u32 o = off0 + i;
            DSL_OPAQUE(o);
            __u8 *p = (__u8 *)app_payload + o;
            if (p + 1 <= (__u8 *)data_end) {
                __u32 t = (p[0] ^ 0x20);
                alive &= (t + 0xFF) >> 8;
                n += alive;
            }
        }
        if (alive || n > 8) return XDP_PASS;
        req.method_off = (__u16)off0;
        req.method_len = (__u16)n;
        cursor = (__u8 *)app_payload + ((off0 + n + 1) & 0x3FFF);
    }
    // req.uri: delimiter " ", value at most 128 byte(s)
    {
        __u32 off0 = ((__u32)((__u8 *)cursor - (__u8 *)app_payload)) & 0x3FFF;
        __u32 n = 0, alive = 1;
        #pragma unroll
        for (int i = 0; i <= 128; i++) {
            __u32 o = off0 + i;
            DSL_OPAQUE(o);
            __u8 *p = (__u8 *)app_payload + o;
            if (p + 1 <= (__u8 *)data_end) {
                __u32 t = (p[0] ^ 0x20);
                alive &= (t + 0xFF) >> 8;
                n += alive;
            }
        }
        if (alive || n > 128) return XDP_PASS;
        req.uri_off = (__u16)off0;
        req.uri_len = (__u16)n;
        cursor = (__u8 *)app_payload + ((off0 + n + 1) & 0x3FFF);
    }
    // req.version: delimiter "\r\n", value at most 16 byte(s)
    {
        __u32 off0 = ((__u32)((__u8 *)cursor - (__u8 *)app_payload)) & 0x3FFF;
        __u32 n = 0, alive = 1;
        #pragma unroll
        for (int i = 0; i <= 16; i++) {
            __u32 o = off0 + i;
            DSL_OPAQUE(o);
            __u8 *p = (__u8 *)app_payload + o;
            if (p + 2 <= (__u8 *)data_end) {
                __u32 t = (p[0] ^ 0x0d) | (p[1] ^ 0x0a);
                alive &= (t + 0xFF) >> 8;
                n += alive;
            }
        }
        if (alive || n > 16) return XDP_PASS;
        req.version_off = (__u16)off0;
        req.version_len = (__u16)n;
        cursor = (__u8 *)app_payload + ((off0 + n + 2) & 0x3FFF);
    }

    // Parse Layout Instance: h1 (Type: Header)
    struct Header_rec h1 = {};
    // h1.name: delimiter ":", value at most 32 byte(s)
    {
        __u32 off0 = ((__u32)((__u8 *)cursor - (__u8 *)app_payload)) & 0x3FFF;
        __u32 n = 0, alive = 1;
        #pragma unroll
        for (int i = 0; i <= 32; i++) {
            __u32 o = off0 + i;
            DSL_OPAQUE(o);
            __u8 *p = (__u8 *)app_payload + o;
            if (p + 1 <= (__u8 *)data_end) {
                __u32 t = (p[0] ^ 0x3a);
                alive &= (t + 0xFF) >> 8;
                n += alive;
            }
        }
        if (alive || n > 32) return XDP_PASS;
        h1.name_off = (__u16)off0;
        h1.name_len = (__u16)n;
        cursor = (__u8 *)app_payload + ((off0 + n + 1) & 0x3FFF);
    }
    // h1.value: delimiter "\r\n", value at most 128 byte(s), whitespace trimmed
    {
        __u32 off0 = ((__u32)((__u8 *)cursor - (__u8 *)app_payload)) & 0x3FFF;
        __u32 n = 0, alive = 1;
        __u32 lead = 0, last = 0, lead_alive = 1;
        #pragma unroll
        for (int i = 0; i <= 128; i++) {
            __u32 o = off0 + i;
            DSL_OPAQUE(o);
            __u8 *p = (__u8 *)app_payload + o;
            if (p + 2 <= (__u8 *)data_end) {
                __u32 t = (p[0] ^ 0x0d) | (p[1] ^ 0x0a);
                alive &= (t + 0xFF) >> 8;
                n += alive;
                __u32 b = p[0];
                __u32 not_blank = (((b ^ 0x20) + 0xFF) >> 8) & (((b ^ 0x09) + 0xFF) >> 8); // not ' ' and not '\t'
                lead_alive &= (not_blank ^ 1) & alive;
                lead += lead_alive;
                __u32 take = 0 - (not_blank & alive);
                DSL_OPAQUE(take);
                last += ((__u32)(i + 1) - last) & take;
            }
        }
        if (alive || n > 128) return XDP_PASS;
        __s32 d = (__s32)last - (__s32)lead;
        __u32 neg = (__u32)(d >> 31);
        DSL_OPAQUE(neg);
        h1.value_off = (__u16)(off0 + lead);
        h1.value_len = (__u16)((__u32)d & ~neg);
        cursor = (__u8 *)app_payload + ((off0 + n + 2) & 0x3FFF);
    }

    // Parse Layout Instance: h2 (Type: Header)
    struct Header_rec h2 = {};
    // h2.name: delimiter ":", value at most 32 byte(s)
    {
        __u32 off0 = ((__u32)((__u8 *)cursor - (__u8 *)app_payload)) & 0x3FFF;
        __u32 n = 0, alive = 1;
        #pragma unroll
        for (int i = 0; i <= 32; i++) {
            __u32 o = off0 + i;
            DSL_OPAQUE(o);
            __u8 *p = (__u8 *)app_payload + o;
            if (p + 1 <= (__u8 *)data_end) {
                __u32 t = (p[0] ^ 0x3a);
                alive &= (t + 0xFF) >> 8;
                n += alive;
            }
        }
        if (alive || n > 32) return XDP_PASS;
        h2.name_off = (__u16)off0;
        h2.name_len = (__u16)n;
        cursor = (__u8 *)app_payload + ((off0 + n + 1) & 0x3FFF);
    }
    // h2.value: delimiter "\r\n", value at most 128 byte(s), whitespace trimmed
    {
        __u32 off0 = ((__u32)((__u8 *)cursor - (__u8 *)app_payload)) & 0x3FFF;
        __u32 n = 0, alive = 1;
        __u32 lead = 0, last = 0, lead_alive = 1;
        #pragma unroll
        for (int i = 0; i <= 128; i++) {
            __u32 o = off0 + i;
            DSL_OPAQUE(o);
            __u8 *p = (__u8 *)app_payload + o;
            if (p + 2 <= (__u8 *)data_end) {
                __u32 t = (p[0] ^ 0x0d) | (p[1] ^ 0x0a);
                alive &= (t + 0xFF) >> 8;
                n += alive;
                __u32 b = p[0];
                __u32 not_blank = (((b ^ 0x20) + 0xFF) >> 8) & (((b ^ 0x09) + 0xFF) >> 8); // not ' ' and not '\t'
                lead_alive &= (not_blank ^ 1) & alive;
                lead += lead_alive;
                __u32 take = 0 - (not_blank & alive);
                DSL_OPAQUE(take);
                last += ((__u32)(i + 1) - last) & take;
            }
        }
        if (alive || n > 128) return XDP_PASS;
        __s32 d = (__s32)last - (__s32)lead;
        __u32 neg = (__u32)(d >> 31);
        DSL_OPAQUE(neg);
        h2.value_off = (__u16)(off0 + lead);
        h2.value_len = (__u16)((__u32)d & ~neg);
        cursor = (__u8 *)app_payload + ((off0 + n + 2) & 0x3FFF);
    }


    // 4. Observability Filters

    // Payload successfully parsed and matched!
    // (Telemetry emission / Ringbuf logic would go here)

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
