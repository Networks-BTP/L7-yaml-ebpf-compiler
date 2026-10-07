#ifndef NETFLOW_XDP_H
#define NETFLOW_XDP_H

#include "netflow_common.h"

#define MAX_FLOW_RECORDS 30

struct NetFlowEvent {
    __u64 timestamp;
    struct NeflowLayout netflowlayout;
};

// Ring buffer for passing Event struct from kernel to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB ring buffer
} events SEC(".maps");

#endif