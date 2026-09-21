#ifndefine VXLAN_XDP_H
#define VXLAN_XDP_H

#include "common.h"

struct VXLAN_XDPEventStruct {
    __u64 timestamp;
    struct VXLANLayout VXLANlayout;
    // What all things would we keep note of
};

// Ring buffer for passing Event struct from kernel to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB ring buffer
} events SEC(".maps");

#endif