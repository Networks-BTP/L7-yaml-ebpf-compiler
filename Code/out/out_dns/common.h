
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

#endif // DNS_COMMON_H
