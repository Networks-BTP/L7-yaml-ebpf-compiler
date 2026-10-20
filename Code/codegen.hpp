#pragma once

#include "analyzer.hpp"
#include <nlohmann/json.hpp>
#include <inja/inja.hpp>
#include <algorithm>
#include <cctype>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace DSLCodeGen {

using json = nlohmann::json;
using DSLAnalyzer::FieldKind;

// True when a field maps to a plain C scalar (as opposed to a byte array).
inline bool is_scalar_field(DataType type, uint32_t size_bytes) {
    if (type == DataType::INT)
        return size_bytes == 1 || size_bytes == 2 || size_bytes == 4 || size_bytes == 8;
    if (type == DataType::BOOLEAN) return size_bytes == 1;
    return false;
}

// Helper to map our AST DataType to standard C/eBPF types.
// Only meaningful for scalar fields; everything else is a __u8 array.
inline std::string map_c_type(DataType type, uint32_t size_bytes) {
    if (type == DataType::INT) {
        if (size_bytes == 1) return "__u8";
        if (size_bytes == 2) return "__u16";
        if (size_bytes == 4) return "__u32";
        if (size_bytes == 8) return "__u64";
    }
    // BOOLEAN, BYTES, STRING, odd-sized ints, floats: raw bytes
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

// Name of the C struct generated for a type.
//  - static types:  the wire layout itself, overlaid directly on the packet ("Header")
//  - dynamic types: a host-order record filled in field by field ("Message_rec")
inline std::string c_struct_name(const DSLAnalyzer::ResolvedType& t) {
    return t.is_dynamic ? t.name + "_rec" : t.name;
}

inline void require_supported_fields(const DSLAnalyzer::ResolvedType& t) {
    for (const auto& f : t.ordered_fields) {
        if (f.kind == FieldKind::DELIMITER || f.kind == FieldKind::VARINT) {
            throw std::runtime_error(std::string("Codegen Error: type '") + t.name + "' uses " +
                                     (f.kind == FieldKind::DELIMITER ? "delimiter" : "varint") + " field '" + f.name +
                                     "', which is not supported yet (only fixed and length_prefixed fields are)");
        }
    }
}

// C expression for the value of `field` of an earlier layout instance, in host byte order.
//  - static source:  the instance is a pointer overlaid on the packet (big-endian) -> byte swap
//  - dynamic source: the instance is a host-order record                             -> plain read
inline std::string length_source_expr(const DSLAnalyzer::ResolvedContext& ctx,
                                      const std::string& src_instance, const std::string& src_field) {
    auto it = std::find_if(ctx.layout.begin(), ctx.layout.end(),
        [&](const DSLAnalyzer::ResolvedLayoutInstance& i) { return i.instance_name == src_instance; });
    const auto& src_type = ctx.types.at(it->type_ref);
    const auto& field = src_type.field_map.at(src_field);

    if (src_type.is_dynamic) return src_instance + "." + src_field;
    std::string access = src_instance + "->" + src_field;
    std::string wrap = ntoh_wrapper(field.max_size);
    return wrap.empty() ? access : wrap + "(" + access + ")";
}

// Emits the C that parses one instance of a dynamic type, field by field, moving `cursor`.
// Every step proves to the eBPF verifier that it stays inside the packet before touching it.
// Values are stored in the record in host byte order; variable-length fields are stored as
// <name>_off (relative to the start of the application payload) and <name>_len.
inline std::string emit_dynamic_parse(const DSLAnalyzer::ResolvedContext& ctx,
                                      const DSLAnalyzer::ResolvedLayoutInstance& instance) {
    const std::string& inst = instance.instance_name;
    const DSLAnalyzer::ResolvedType& t = ctx.types.at(instance.type_ref);
    require_supported_fields(t);

    std::ostringstream o;
    const auto& fields = t.ordered_fields;
    size_t i = 0;

    while (i < fields.size()) {
        const auto& f = fields[i];

        if (f.kind == FieldKind::FIXED) {
            // Coalesce consecutive fixed fields into one run: a single bounds check, then loads.
            size_t j = i;
            uint32_t run = 0;
            while (j < fields.size() && fields[j].kind == FieldKind::FIXED) {
                run += fields[j].max_size;
                ++j;
            }

            o << "    // " << inst << ": fixed run of " << run << " byte(s)\n";
            o << "    if ((__u8 *)cursor + " << run << " > (__u8 *)data_end) return XDP_PASS;\n";

            uint32_t off = 0;
            for (size_t k = i; k < j; ++k) {
                const auto& g = fields[k];
                const std::string lhs = inst + "." + g.name;
                const std::string src = "(__u8 *)cursor + " + std::to_string(off);

                if (is_scalar_field(g.data_type, g.max_size)) {
                    std::string load = "DSL_LOAD(" + map_c_type(g.data_type, g.max_size) + ", " + src + ")";
                    std::string wrap = (g.data_type == DataType::INT) ? ntoh_wrapper(g.max_size) : "";
                    o << "    " << lhs << " = " << (wrap.empty() ? load : wrap + "(" + load + ")") << ";\n";
                } else {
                    o << "    __builtin_memcpy(" << lhs << ", " << src << ", " << g.max_size << ");\n";
                }
                off += g.max_size;
            }
            o << "    cursor = (__u8 *)cursor + " << run << ";\n";
            i = j;
        }
        else if (f.kind == FieldKind::LENGTH_PREFIXED) {
            const std::string base = inst + "." + f.name;

            // Where the length comes from, and the per-instance numbers when it lives in another struct.
            std::string length_expr, length_desc;
            uint32_t cap = f.max_size, multiplier = f.multiplier;
            int32_t addend = f.addend;
            if (f.external_length) {
                const auto& b = instance.external_lengths.at(f.name);
                length_expr = length_source_expr(ctx, b.src_instance, b.src_field);
                length_desc = b.src_instance + "." + b.src_field;
                cap = b.max_bytes;
                multiplier = b.multiplier;
                addend = b.addend;
            } else {
                length_expr = inst + "." + f.length_field;
                length_desc = length_expr;
            }

            o << "    // " << base << ": length-prefixed, size = " << length_desc
              << " * " << multiplier << " + (" << addend << "), at most " << cap << " byte(s)\n";
            o << "    {\n";
            o << "        __s64 n = (__s64)" << length_expr << " * " << multiplier
              << " + (" << addend << ");\n";
            o << "        if (n < 0 || n > " << cap << ") return XDP_PASS;\n";
            o << "        if ((__u8 *)cursor + n > (__u8 *)data_end) return XDP_PASS;\n";
            o << "        " << base << "_off = (__u16)((__u8 *)cursor - (__u8 *)app_payload);\n";
            o << "        " << base << "_len = (__u16)n;\n";
            o << "        cursor = (__u8 *)cursor + n;\n";
            o << "    }\n";
            ++i;
        }
    }

    std::string code = o.str();
    if (!code.empty() && code.back() == '\n') code.pop_back(); // the template adds the newline
    return code;
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
        require_supported_fields(r_type);

        json struct_json;
        struct_json["c_name"] = c_struct_name(r_type);
        struct_json["attr"] = r_type.is_dynamic ? "" : " __attribute__((packed))"; // wire overlay is packed; the record is not
        struct_json["fields"] = json::array();

        for (const auto& r_field : r_type.ordered_fields) {
            json field_json;
            field_json["name"] = r_field.name;
            field_json["c_type"] = map_c_type(r_field.data_type, r_field.max_size);
            field_json["is_view"] = false;
            field_json["is_array"] = false;

            if (r_field.kind == FieldKind::LENGTH_PREFIXED) {
                // Variable-length bytes are not copied; the record keeps where they are.
                field_json["is_view"] = true;
            } else if (!is_scalar_field(r_field.data_type, r_field.max_size)) {
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
        const auto& r_type = ctx.types.at(l_inst.type_ref);
        json l_json;
        l_json["instance_name"] = l_inst.instance_name;
        l_json["type_ref"] = l_inst.type_ref;
        l_json["c_struct"] = c_struct_name(r_type);
        l_json["is_dynamic"] = r_type.is_dynamic;
        l_json["parse_code"] = r_type.is_dynamic ? emit_dynamic_parse(ctx, l_inst) : "";
        data["layout"].push_back(l_json);
    }

    // Map Filters: only fixed-size scalar integer fields can be compared in C.
    data["filters"] = json::array();
    for (const auto& f : ctx.filters) {
        const auto& inst = *std::find_if(ctx.layout.begin(), ctx.layout.end(),
            [&](const DSLAnalyzer::ResolvedLayoutInstance& i) { return i.instance_name == f.layout_instance; });
        const auto& r_type = ctx.types.at(inst.type_ref);
        const auto& r_field = r_type.field_map.at(f.field_name);

        if (r_field.kind != FieldKind::FIXED || r_field.data_type != DataType::INT ||
            !is_scalar_field(r_field.data_type, r_field.max_size)) {
            std::cerr << "[Codegen] Warning: filter on '" << f.layout_instance << "." << f.field_name
                      << "' skipped (only fixed-size scalar integer fields are supported)\n";
            continue;
        }

        // Static types are overlaid on the packet (big-endian, needs a byte swap);
        // dynamic records already hold host-order values.
        std::string lhs;
        if (r_type.is_dynamic) {
            lhs = f.layout_instance + "." + f.field_name;
        } else {
            std::string access = f.layout_instance + "->" + f.field_name;
            std::string wrap = ntoh_wrapper(r_field.max_size);
            lhs = wrap.empty() ? access : wrap + "(" + access + ")";
        }

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

        json fj;
        fj["lhs"] = lhs;
        fj["op"] = filter_op_to_c(f.op);
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
struct {{ struct.c_name }} {
## for field in struct.fields
## if field.is_view
    __u16 {{ field.name }}_off; // offset from the start of the application payload
    __u16 {{ field.name }}_len;
## else
    {{ field.c_type }} {{ field.name }}{% if field.is_array %}[{{ field.array_size }}]{% endif %};
## endif
## endfor
}{{ struct.attr }};

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

// Unaligned-safe load of a fixed-size value from packet memory.
#define DSL_LOAD(type, p) ({ type _v; __builtin_memcpy(&_v, (p), sizeof(_v)); _v; })

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
    struct {{ item.c_struct }} {{ item.instance_name }} = {};
{{ item.parse_code }}
## else
    struct {{ item.c_struct }} *{{ item.instance_name }} = cursor;
    if ((void *)({{ item.instance_name }} + 1) > data_end) return XDP_PASS;
    cursor = (void *)({{ item.instance_name }} + 1);
## endif

## endfor

    // 4. Observability Filters
## for f in filters
    if (!({{ f.lhs }} {{ f.op }} {{ f.value }})) return XDP_PASS;
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