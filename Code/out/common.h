
#ifndef TOYPROTO_COMMON_H
#define TOYPROTO_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>

struct Header {
    __u16 magic;
    __u8 version;
    __u8 opcode;
    __u16 length;
    __u32 request_id;
} __attribute__((packed));

struct Body {
    __u8 key[8];
    __u16 flags;
} __attribute__((packed));

#endif // TOYPROTO_COMMON_H
