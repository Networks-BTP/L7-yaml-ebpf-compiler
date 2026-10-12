#pragma once

#include "analyzer.hpp"
#include <nlohmann/json.hpp>
#include <inja/inja.hpp>
#include <algorithm>
#include <cctype>
#include <string>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace DSLCodeGen {

using json = nlohmann::json;

// True when a field maps to a plain C scalar (as opposed to a byte array).
inline bool is_scalar_field(DataType type, uint32_t size_bytes) {
    if (type == DataType::INT)
        return size_bytes == 1 || size_bytes == 2 || size_bytes == 4 || size_bytes == 8;
    if (type == DataType::BOOLEAN) return true;
    return false;
}

// Helper to map our AST DataType to standard C/eBPF types.
// Only meaningful for scalar fields; everything else is a uint8_t array.
inline std::string map_c_type(DataType type, uint32_t size_bytes) {
    if (type == DataType::INT) {
        if (size_bytes == 1) return "__u8";
        if (size_bytes == 2) return "__u16";
        if (size_bytes == 4) return "__u32";
        if (size_bytes == 8) return "__u64";
    }
    if (type == DataType::BOOLEAN) return "__u8";
    // BYTES, STRING, odd-sized ints, floats: raw byte array
    return "__u8";
}

inline std::string filter_op_to_c(FilterOp op) {
    switch (op) {
        case FilterOp::EQUAL:        return "==";
        case FilterOp::NOT_EQUAL:    return "!=";
        case FilterOp::GREATER_THAN: return ">";
        case FilterOp::LESS_THAN:    return "<";
    }
    return "==";
}

// Network-to-host conversion wrapper for a given scalar size (protocol fields are big-endian).
inline std::string ntoh_wrapper(uint32_t size_bytes) {
    if (size_bytes == 2) return "bpf_ntohs";
    if (size_bytes == 4) return "bpf_ntohl";
    if (size_bytes == 8) return "bpf_be64_to_cpu";
    return ""; // 1 byte: no swap needed
}

// 1. Context to JSON Mapper
inline json build_template_context(const DSLAnalyzer::ResolvedContext& ctx) {
    json data;
    std::string upper = ctx.protocol_name;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    data["protocol"] = ctx.protocol_name;
    data["protocol_upper"] = upper;
    data["transport"] = ctx.transport;
    data["port"] = ctx.port;

    // Map Types to C Structs (declaration order -> deterministic output)
    data["structs"] = json::array();
    for (const auto& name : ctx.type_order) {
        const auto& r_type = ctx.types.at(name);

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

            if (is_scalar_field(r_field.data_type, r_field.max_size)) {
                field_json["is_array"] = false;
            } else {
                field_json["is_array"] = true;
                field_json["array_size"] = r_field.max_size;
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

    // Map Filters: only scalar integer fields of static types can be compared in C.
    data["filters"] = json::array();
    for (const auto& f : ctx.filters) {
        const auto& inst = *std::find_if(ctx.layout.begin(), ctx.layout.end(),
            [&](const DSLAnalyzer::ResolvedLayoutInstance& i) { return i.instance_name == f.layout_instance; });
        const auto& r_type = ctx.types.at(inst.type_ref);
        if (r_type.is_dynamic) continue;

        const auto& r_field = r_type.field_map.at(f.field_name);
        if (r_field.data_type != DataType::INT || !is_scalar_field(r_field.data_type, r_field.max_size)) {
            std::cerr << "[Codegen] Warning: filter on '" << f.layout_instance << "." << f.field_name
                      << "' skipped (only scalar integer fields are supported)\n";
            continue;
        }

        json fj;
        fj["instance_name"] = f.layout_instance;
        fj["field_name"] = f.field_name;
        fj["op"] = filter_op_to_c(f.op);
        fj["ntoh"] = ntoh_wrapper(r_field.max_size);
        // Value is emitted into C source, so require a plain integer literal.
        size_t consumed = 0;
        unsigned long long numeric = 0;
        try {
            numeric = std::stoull(f.value, &consumed, 0);
        } catch (...) {
            consumed = 0;
        }
        if (consumed == 0 || consumed != f.value.size()) {
            throw std::runtime_error("Codegen Error: filter value '" + f.value + "' for '" +
                                     f.layout_instance + "." + f.field_name + "' is not an integer");
        }
        fj["value"] = std::to_string(numeric) + "ULL";
        data["filters"].push_back(fj);
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
#include <linux/in.h>
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

    // 4. Observability Filters
## for f in filters
    if (!({{ f.ntoh }}({{ f.instance_name }}->{{ f.field_name }}) {{ f.op }} {{ f.value }})) return XDP_PASS;
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
    if (!out_h) throw std::runtime_error("Codegen Error: cannot write " + out_dir + "/common.h");
    out_h << common_h;
    out_h.close();

    std::ofstream out_c(out_dir + "/tracer.bpf.c");
    if (!out_c) throw std::runtime_error("Codegen Error: cannot write " + out_dir + "/tracer.bpf.c");
    out_c << tracer_c;
    out_c.close();

    std::cout << "[Codegen] Successfully generated common.h and tracer.bpf.c\n";
}

} // namespace DSLCodeGen