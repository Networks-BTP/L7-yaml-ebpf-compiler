#pragma once

#include "analyzer.hpp"
#include <nlohmann/json.hpp>
#include <inja/inja.hpp>
#include <string>
#include <fstream>
#include <iostream>

namespace DSLCodeGen {

using json = nlohmann::json;

// Helper to map our AST DataType to standard C/eBPF types
inline std::string map_c_type(DSLAnalyzer::DataType type, uint32_t size_bytes) {
    if (type == DSLAnalyzer::DataType::INT) {
        if (size_bytes == 1) return "uint8_t";
        if (size_bytes == 2) return "uint16_t";
        if (size_bytes == 4) return "uint32_t";
        if (size_bytes == 8) return "uint64_t";
    }
    // For BYTES, STRING, or unknown sizes, fallback to a byte array
    return "uint8_t";
}

// 1. Context to JSON Mapper
inline json build_template_context(const DSLAnalyzer::ResolvedContext& ctx) {
    json data;
    data["protocol"] = ctx.protocol_name;
    data["protocol_upper"] = ctx.protocol_name;
    std::transform(data["protocol_upper"].get_ref<std::string&>().begin(), 
                   data["protocol_upper"].get_ref<std::string&>().end(), 
                   data["protocol_upper"].get_ref<std::string&>().begin(), ::toupper);
                   
    data["transport"] = ctx.transport;
    data["port"] = ctx.port;

    // Map Types to C Structs
    data["structs"] = json::array();
    for (const auto& [name, r_type] : ctx.types) {
        // We only generate static structs for non-dynamic types.
        // Variable-length types must be parsed byte-by-byte in XDP.
        if (r_type.is_dynamic) continue;

        json struct_json;
        struct_json["name"] = name;
        struct_json["fields"] = json::array();

        for (const auto& r_field : r_type.ordered_fields) {
            json field_json;
            field_json["name"] = r_field.name;
            field_json["c_type"] = map_c_type(r_field.data_type, r_field.max_size);
            
            // If it's a byte array/string, we need array syntax in C
            if (r_field.data_type == DSLAnalyzer::DataType::BYTES || 
                r_field.data_type == DSLAnalyzer::DataType::STRING) {
                field_json["is_array"] = true;
                field_json["array_size"] = r_field.max_size;
            } else {
                field_json["is_array"] = false;
            }
            
            struct_json["fields"].push_back(field_json);
        }
        data["structs"].push_back(struct_json);
    }

    // Map Layout for the XDP execution flow
    data["layout"] = json::array();
    for (const auto& l_inst : ctx.layout) {
        json l_json;
        l_json["instance_name"] = l_inst.instance_name;
        l_json["type_ref"] = l_inst.type_ref;
        l_json["is_dynamic"] = ctx.types.at(l_inst.type_ref).is_dynamic;
        data["layout"].push_back(l_json);
    }

    return data;
}

// 2. Jinja Templates

const char* TEMPLATE_COMMON_H = R"(
#ifndef {{ protocol_upper }}_COMMON_H
#define {{ protocol_upper }}_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>

## for struct in structs
struct {{ struct.name }} {
## for field in struct.fields
    {{ field.c_type }} {{ field.name }}{% if field.is_array %}[{{ field.array_size }}]{% endif %};
## endfor
} __attribute__((packed));

## endfor
#endif // {{ protocol_upper }}_COMMON_H
)";

const char* TEMPLATE_TRACER_C = R"(
#include "common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_{{ protocol }}_parser(struct xdp_md *ctx) {
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
## if transport == "tcp"
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
    struct tcphdr *l4 = (void *)ip + ip_hdr_len;
    if ((void *)(l4 + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(l4->dest) != {{ port }} && bpf_ntohs(l4->source) != {{ port }}) return XDP_PASS;
    void *app_payload = (void *)l4 + (l4->doff * 4);
## else
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *l4 = (void *)ip + ip_hdr_len;
    if ((void *)(l4 + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(l4->dest) != {{ port }} && bpf_ntohs(l4->source) != {{ port }}) return XDP_PASS;
    void *app_payload = (void *)(l4 + 1);
## endif

    // 3. Application Protocol Layout Parsing
    void *cursor = app_payload;

## for item in layout
    // Parse Layout Instance: {{ item.instance_name }} (Type: {{ item.type_ref }})
## if item.is_dynamic
    // Notice: Type is dynamic. Requires byte-by-byte parsing (eBPF loop limits apply).
    // ... Dynamic parsing logic goes here ...
## else
    struct {{ item.type_ref }} *{{ item.instance_name }} = cursor;
    if ((void *)({{ item.instance_name }} + 1) > data_end) return XDP_PASS;
    cursor = (void *)({{ item.instance_name }} + 1);
## endif

## endfor

    // Payload successfully parsed and matched!
    // (Telemetry emission / Ringbuf logic would go here)
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
)";

// 3. Execution Function
inline void generate(const DSLAnalyzer::ResolvedContext& ctx, const std::string& out_dir = ".") {
    json data = build_template_context(ctx);
    inja::Environment env;
    env.set_trim_blocks(true);
    env.set_lstrip_blocks(true);

    std::string common_h = env.render(TEMPLATE_COMMON_H, data);
    std::string tracer_c = env.render(TEMPLATE_TRACER_C, data);

    std::ofstream out_h(out_dir + "/common.h");
    out_h << common_h;
    out_h.close();

    std::ofstream out_c(out_dir + "/tracer.bpf.c");
    out_c << tracer_c;
    out_c.close();

    std::cout << "[Codegen] Successfully generated common.h and tracer.bpf.c\n";
}

} // namespace DSLCodeGen