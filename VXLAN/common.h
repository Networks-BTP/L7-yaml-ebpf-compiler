#ifndef VXLAN_COMMON_H
#define VXLAN_COMMON_H

// eBPF helper headers
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Constants

// Structs

// 20 bytes
struct InnerIPHeader{
    char padding_0[9];
    uint8_t protocol;
    char padding_1[2];
    uint32_t src_ip;
    uint32_t dst_ip;
}; __attribute__((packed));

// 14 bytes
struct InnerEthernetHeader{
    char padding_0[12];
    uint16_t ether_type;
}; __attribute__((packed));

struct VxlanHeader{
    uint8_t flags;
    char padding_0[3];
    uint8_t vni[3];
    char padding_1[1];
}; __attribute__((packed));

struct VXLANLayout{
    VxlanHeader vxlan;
    InnerEthernetHeader inner_eth;
    InnerIPHeader inner_ip;
}; __attribute__((packed));

// Maybe enums

// Stat Maps maybe -> Will come back later

#endif