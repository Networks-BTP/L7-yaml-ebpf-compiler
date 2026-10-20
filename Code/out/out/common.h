
#ifndef CROSSPROTO_COMMON_H
#define CROSSPROTO_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>

struct Header {
    __u16 magic;
    __u8 len_a;
    __u8 len_b;
} __attribute__((packed));

struct Chunk_rec {
    __u16 data_off; // offset from the start of the application payload
    __u16 data_len;
    __u8 tail;
};

#endif // CROSSPROTO_COMMON_H
