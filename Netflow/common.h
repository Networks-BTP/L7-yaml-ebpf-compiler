#ifndef NETFLOW_COMMON_H
#define NETFLOW_COMMON_H

// eBPF helper headers
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Constants
#define MAX_FLOW_RECORDS 30

// Structs

// 48 bytes
struct FlowRecord{
    __u32 src_ip;
    __u32 dst_ip;
    __u32 next_hop;
    __u16 input_snmp;
    __u16 output_snmp;
    __u32 packets;
    __u32 octets;
    __u8 padding_0[8];
    __u16 src_port;
    __u16 dst_port;
    __u8 tcp_flags;
    __u8 padding_1[11];
}; __attribute__((packed));


// 24 bytes
struct NetflowHeader{
    __u16 version;
    __u16 count;
    __u32 uptime;
    __u8 padding_0[16];
}; __attribute__((packed));

struct NetflowLayout {
    struct NetflowHeader netflowheader;
    struct FlowRecord flowrecord[MAX_FLOW_RECORDS];
} __attribute__((packed));

// Maybe enums

// Stat Maps maybe -> Will come back later

#endif