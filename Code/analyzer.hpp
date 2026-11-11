#pragma once

#include "ast.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

namespace DSLAnalyzer {

// Helper: Extract FieldBase from variant
inline const FieldBase& get_field_base(const FieldNode& node) {
    return std::visit([](const auto& f) -> const FieldBase& {
        return static_cast<const FieldBase&>(f);
    }, node);
}

// --- Resolved Symbol Table Data Structures ---

enum class FieldKind { FIXED, LENGTH_PREFIXED, DELIMITER, VARINT };

struct ResolvedField {
    std::string name;
    DataType data_type{DataType::INT};
    FieldKind kind{FieldKind::FIXED};

    // Static offset from the start of the type. Only meaningful while
    // offset_is_static is true (i.e. no dynamic field precedes this one).
    uint32_t offset{0};
    bool offset_is_static{true};

    // FIXED: size in bytes.
    // LENGTH_PREFIXED / DELIMITER / VARINT: cap on the field's own bytes
    //   (the hard bound the eBPF verifier needs).
    // For a LENGTH_PREFIXED field whose length lives in another layout instance
    // (external_length) this is the largest cap over all instances using the type.
    uint32_t max_size{0};
    bool is_dynamic{false};

    // LENGTH_PREFIXED, length in the same type: size = value(length_field) * multiplier + addend
    std::string length_field;
    uint32_t multiplier{1};
    int32_t addend{0};

    // LENGTH_PREFIXED, length in another layout instance: the binding differs per
    // instance and lives in ResolvedLayoutInstance::external_lengths.
    bool external_length{false};

    // DELIMITER
    std::string marker;
    bool trim_whitespace{false};
};

struct ResolvedType {
    std::string name;
    uint32_t static_min_size{0}; // Minimum bytes the type consumes on the wire
    uint32_t static_max_size{0}; // Maximum bytes the type consumes on the wire
    bool is_dynamic{false};      // True if it contains variable-length fields
    std::unordered_map<std::string, ResolvedField> field_map;
    std::vector<ResolvedField> ordered_fields; // Wire order == parse order
};

// A length-prefixed field whose length value is a field of an *earlier layout instance*.
struct ExternalLength {
    std::string src_instance;
    std::string src_field;
    uint32_t max_bytes{0};
    uint32_t multiplier{1};
    int32_t addend{0};
};

// Bounded repetition of a layout instance (see LayoutNode::repeat_expr).
struct RepeatSpec {
    bool is_constant{false};
    uint32_t constant{0};          // is_constant: the fixed count
    std::string src_instance;      // !is_constant: earlier, non-repeated instance holding the count ...
    std::string src_field;         // ... and its fixed 1/2/4/8-byte integer field
    uint32_t max{0};               // hard cap (== constant when is_constant); a larger count rejects the message
};

struct ResolvedLayoutInstance {
    std::string instance_name;
    std::string type_ref;
    std::map<std::string, ExternalLength> external_lengths; // keyed by length-prefixed field name
    std::optional<RepeatSpec> repeat;                       // set when the instance is repeated
};

struct ResolvedFilter {
    std::string layout_instance;
    std::string field_name;
    FilterOp op;
    std::string value;
    std::optional<uint32_t> index; // element index, for filters on a repeated instance: answers[1].rtype
};

struct ResolvedContext {
    std::string protocol_name;
    std::string transport;
    uint16_t port{0};
    std::unordered_map<std::string, ResolvedType> types;
    std::vector<std::string> type_order; // Declaration order, so generated C is deterministic
    std::vector<ResolvedLayoutInstance> layout;
    std::vector<ResolvedFilter> filters;
};

// --- Helpers ---

// Names end up as C identifiers in generated code, so they must be valid ones.
inline void require_c_ident(const std::string& name, const std::string& what) {
    bool ok = !name.empty() && (std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_');
    for (char c : name) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) ok = false;
    }
    if (!ok) {
        throw std::runtime_error("Semantic Error: " + what + " '" + name +
                                 "' is not a valid C identifier (letters, digits, '_'; must not start with a digit)");
    }
}

// Names the generated XDP function already uses for its own variables.
inline bool is_reserved_instance_name(const std::string& name) {
    static const std::set<std::string> reserved = {
        "ctx", "data", "data_end", "eth", "ip", "ip_hdr_len", "l4", "app_payload", "cursor"
    };
    return reserved.count(name) > 0;
}

inline bool is_scalar_int_size(uint32_t n) { return n == 1 || n == 2 || n == 4 || n == 8; }

// Minimum / maximum bytes a type consumes on the wire, from its (resolved) fields.
inline void recompute_sizes(ResolvedType& t) {
    t.static_min_size = 0;
    t.static_max_size = 0;
    for (const auto& f : t.ordered_fields) {
        uint32_t mn = 0, mx = 0;
        switch (f.kind) {
            case FieldKind::FIXED:           mn = mx = f.max_size; break;
            case FieldKind::LENGTH_PREFIXED: mn = 0; mx = f.max_size; break;
            case FieldKind::DELIMITER:
                mn = static_cast<uint32_t>(f.marker.size());
                mx = f.max_size + static_cast<uint32_t>(f.marker.size());
                break;
            case FieldKind::VARINT:          mn = 1; mx = f.max_size; break;
        }
        t.static_min_size += mn;
        t.static_max_size += mx;
    }
}

inline const TypeDefNode* find_type_node(const ProtocolAST& ast, const std::string& name) {
    for (const auto& t : ast.types) if (t.name == name) return &t;
    return nullptr;
}

inline bool type_has_lp_field(const TypeDefNode& t, const std::string& field) {
    for (const auto& fv : t.fields) {
        if (std::holds_alternative<LengthPrefixedFieldNode>(fv) && get_field_base(fv).name == field) return true;
    }
    return false;
}

// Splits "inst.field" (exactly one dot, both sides non-empty).
inline bool split_instance_ref(const std::string& ref, std::string& inst, std::string& field) {
    size_t dot = ref.find('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= ref.size()) return false;
    if (ref.find('.', dot + 1) != std::string::npos) return false;
    inst = ref.substr(0, dot);
    field = ref.substr(dot + 1);
    return true;
}

// Largest repeat count accepted; every repetition is unrolled into the program.
constexpr uint32_t MAX_REPEAT_LIMIT = 16;

// Splits a filter target: "inst.field" or "inst[N].field".
inline bool split_filter_target(const std::string& ref, std::string& inst,
                                std::optional<uint32_t>& index, std::string& field) {
    size_t dot = ref.find('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= ref.size()) return false;
    std::string lhs = ref.substr(0, dot);
    field = ref.substr(dot + 1);
    index.reset();

    size_t br = lhs.find('[');
    if (br == std::string::npos) { inst = lhs; return true; }
    if (br == 0 || lhs.back() != ']' || br + 2 > lhs.size() - 1) return false;
    std::string digits = lhs.substr(br + 1, lhs.size() - br - 2);
    if (digits.empty() || digits.size() > 6 ||
        !std::all_of(digits.begin(), digits.end(), [](unsigned char c) { return std::isdigit(c); })) return false;
    inst = lhs.substr(0, br);
    index = static_cast<uint32_t>(std::stoul(digits));
    return true;
}

// --- Analysis Logic ---

inline ResolvedContext analyze(const ProtocolAST& ast) {
    ResolvedContext ctx;
    ctx.protocol_name = ast.protocol_name;
    ctx.transport = ast.transport;
    ctx.port = ast.default_port;

    require_c_ident(ast.protocol_name, "protocol name");

    // instance name -> type name (needed before types are resolved, to bind cross-struct lengths)
    std::map<std::string, std::string> instance_type;
    for (const auto& l : ast.layout) instance_type[l.instance_name] = l.type_ref;

    // 0. Bind entries of the separate `lp_resolutions` section to the length-prefixed field they describe.
    //    length_name "len"       -> same-type length, bound per (type, field)
    //    length_name "inst.len"  -> length in an earlier layout instance, bound per (instance, field)
    std::map<std::pair<std::string, std::string>, const LengthPrefixedResolution*> lp_sections;   // (type, field)
    std::map<std::pair<std::string, std::string>, const LengthPrefixedResolution*> ext_sections;  // (instance, field)

    for (const auto& res : ast.LPresolution) {
        std::string src_inst, src_field;
        const bool dotted = res.length_name.find('.') != std::string::npos;

        if (!dotted) {
            if (res.instance_name) {
                throw std::runtime_error("Semantic Error: LP resolution for field '" + res.field_name +
                                         "': 'instance:' only makes sense with a cross-struct length_name like 'hdr.length'");
            }
            std::vector<std::string> owners;
            for (const auto& t : ast.types) {
                if (res.type_name && *res.type_name != t.name) continue;
                if (type_has_lp_field(t, res.field_name)) owners.push_back(t.name);
            }
            std::string where = res.type_name ? " in type '" + *res.type_name + "'" : "";
            if (owners.empty()) {
                throw std::runtime_error("Semantic Error: LP resolution refers to length-prefixed field '" +
                                         res.field_name + "'" + where + ", which does not exist");
            }
            if (owners.size() > 1) {
                throw std::runtime_error("Semantic Error: LP resolution for field '" + res.field_name +
                                         "' is ambiguous (it exists in several types); add 'type: <TypeName>'");
            }
            auto key = std::make_pair(owners[0], res.field_name);
            if (!lp_sections.emplace(key, &res).second) {
                throw std::runtime_error("Semantic Error: duplicate LP resolution for field '" + res.field_name +
                                         "' in type '" + owners[0] + "'");
            }
            continue;
        }

        if (!split_instance_ref(res.length_name, src_inst, src_field)) {
            throw std::runtime_error("Semantic Error: LP resolution for field '" + res.field_name + "': length_name '" +
                                     res.length_name + "' must be 'field' or 'instance.field'");
        }
        if (res.instance_name && !instance_type.count(*res.instance_name)) {
            throw std::runtime_error("Semantic Error: LP resolution for field '" + res.field_name +
                                     "': layout instance '" + *res.instance_name + "' does not exist");
        }
        std::vector<std::string> targets; // layout instances this entry could apply to
        for (const auto& l : ast.layout) {
            if (res.instance_name && *res.instance_name != l.instance_name) continue;
            if (res.type_name && *res.type_name != l.type_ref) continue;
            const TypeDefNode* tn = find_type_node(ast, l.type_ref);
            if (tn && type_has_lp_field(*tn, res.field_name)) targets.push_back(l.instance_name);
        }
        if (targets.empty()) {
            throw std::runtime_error("Semantic Error: LP resolution for length-prefixed field '" + res.field_name +
                                     "' matches no layout instance");
        }
        if (targets.size() > 1) {
            throw std::runtime_error("Semantic Error: LP resolution for field '" + res.field_name +
                                     "' matches several layout instances; add 'instance: <name>'");
        }
        if (!ext_sections.emplace(std::make_pair(targets[0], res.field_name), &res).second) {
            throw std::runtime_error("Semantic Error: duplicate LP resolution for field '" + res.field_name +
                                     "' of layout instance '" + targets[0] + "'");
        }
    }

    // True when some instance of `type_name` has a cross-struct length bound to `field`.
    auto has_external_binding = [&](const std::string& type_name, const std::string& field) {
        for (const auto& kv : ext_sections) {
            if (kv.first.second != field) continue;
            auto it = instance_type.find(kv.first.first);
            if (it != instance_type.end() && it->second == type_name) return true;
        }
        return false;
    };

    // 1. Resolve Types: walk fields in wire order, bind same-type length fields.
    for (const auto& type_node : ast.types) {
        require_c_ident(type_node.name, "type name");
        if (ctx.types.count(type_node.name)) {
            throw std::runtime_error("Semantic Error: Duplicate type name '" + type_node.name + "'");
        }

        ResolvedType r_type;
        r_type.name = type_node.name;
        uint32_t running_offset = 0;   // static offset of the next field
        bool after_dynamic = false;    // once true, static offsets no longer exist

        for (const auto& field_variant : type_node.fields) {
            const FieldBase& base = get_field_base(field_variant);
            const std::string where = "field '" + base.name + "' in type '" + type_node.name + "'";

            require_c_ident(base.name, "field name in type '" + type_node.name + "'");
            if (r_type.field_map.count(base.name)) {
                throw std::runtime_error("Semantic Error: Duplicate field name '" + base.name +
                                         "' in type '" + type_node.name + "'");
            }

            // Explicit offsets are only accepted when they match where the field lands anyway.
            // (Gaps/overlaps and offset expressions would otherwise be silently ignored.)
            if (base.offset_expr) {
                size_t consumed = 0;
                unsigned long requested = 0;
                try { requested = std::stoul(*base.offset_expr, &consumed, 0); } catch (...) { consumed = 0; }
                if (consumed == 0 || consumed != base.offset_expr->size()) {
                    throw std::runtime_error("Semantic Error: " + where + ": offset expressions are not supported yet ('" +
                                             *base.offset_expr + "')");
                }
                if (after_dynamic) {
                    throw std::runtime_error("Semantic Error: " + where +
                                             ": explicit offset after a variable-length field is not supported");
                }
                if (requested != running_offset) {
                    throw std::runtime_error("Semantic Error: " + where + ": explicit offset " + std::to_string(requested) +
                                             " differs from the running offset " + std::to_string(running_offset) +
                                             " (gaps and overlaps are not supported yet)");
                }
            }

            ResolvedField r_field;
            r_field.name = base.name;
            r_field.data_type = base.data_type;
            r_field.offset = running_offset;
            r_field.offset_is_static = !after_dynamic;

            uint32_t advance = 0; // bytes the static offset moves (fixed fields only)

            std::visit([&](const auto& concrete) {
                using T = std::decay_t<decltype(concrete)>;

                if constexpr (std::is_same_v<T, FixedFieldNode>) {
                    if (concrete.size_bytes == 0) {
                        throw std::runtime_error("Semantic Error: " + where + ": size must be greater than 0");
                    }
                    r_field.kind = FieldKind::FIXED;
                    r_field.max_size = concrete.size_bytes;
                    r_field.is_dynamic = false;
                    advance = concrete.size_bytes;
                }
                else if constexpr (std::is_same_v<T, LengthPrefixedFieldNode>) {
                    // Inline values first; a same-type lp_resolutions entry (if any) overrides them.
                    std::optional<std::string> len_field = concrete.length_field;
                    std::optional<uint32_t> max_bytes = concrete.max_bytes;
                    uint32_t multiplier = concrete.multiplier;
                    int32_t addend = concrete.addend;

                    if (len_field && len_field->find('.') != std::string::npos) {
                        throw std::runtime_error("Semantic Error: length-prefixed " + where + ": length_field '" + *len_field +
                                                 "' points into another layout instance; cross-struct lengths are bound per "
                                                 "instance in lp_resolutions (instance: <name>, length_name: <inst.field>)");
                    }

                    auto sec = lp_sections.find({type_node.name, base.name});
                    if (sec != lp_sections.end()) {
                        len_field = sec->second->length_name;
                        max_bytes = sec->second->max_bytes;
                        multiplier = sec->second->multiplier;
                        addend = sec->second->addend;
                    }

                    const bool external = has_external_binding(type_node.name, base.name);

                    if (len_field && external) {
                        throw std::runtime_error("Semantic Error: length-prefixed " + where + " has a length in the same type ('" +
                                                 *len_field + "') and is also bound to another instance's length by lp_resolutions; use one");
                    }

                    if (!len_field) {
                        if (!external) {
                            throw std::runtime_error("Semantic Error: length-prefixed " + where +
                                                     " has no length source (give 'length_field:' on the field, or an lp_resolutions entry; "
                                                     "for a length in another struct use 'instance:' and 'length_name: <inst.field>')");
                        }
                        // Length comes from another layout instance; the binding (and cap) is per instance
                        // and is resolved with the layout below.
                        r_field.kind = FieldKind::LENGTH_PREFIXED;
                        r_field.is_dynamic = true;
                        r_field.external_length = true;
                    } else {
                        if (!max_bytes || *max_bytes == 0) {
                            throw std::runtime_error("Semantic Error: length-prefixed " + where +
                                                     " needs 'max_bytes' > 0 (the eBPF verifier requires a hard cap)");
                        }
                        if (multiplier == 0) {
                            throw std::runtime_error("Semantic Error: length-prefixed " + where + ": multiplier must not be 0");
                        }

                        auto lit = r_type.field_map.find(*len_field);
                        if (lit == r_type.field_map.end()) {
                            throw std::runtime_error("Semantic Error: length-prefixed " + where + ": length field '" + *len_field +
                                                     "' must be declared earlier in the same type (for a length in another "
                                                     "struct use lp_resolutions with 'instance:' and 'length_name: <inst.field>')");
                        }
                        const ResolvedField& lf = lit->second;
                        bool len_ok = lf.data_type == DataType::INT &&
                                      ((lf.kind == FieldKind::FIXED && is_scalar_int_size(lf.max_size)) ||
                                       lf.kind == FieldKind::VARINT);
                        if (!len_ok) {
                            throw std::runtime_error("Semantic Error: length-prefixed " + where + ": length field '" + *len_field +
                                                     "' must be an integer (fixed 1/2/4/8 bytes, or varint)");
                        }

                        r_field.kind = FieldKind::LENGTH_PREFIXED;
                        r_field.is_dynamic = true;
                        r_field.max_size = *max_bytes;
                        r_field.length_field = *len_field;
                        r_field.multiplier = multiplier;
                        r_field.addend = addend;
                    }
                }
                else if constexpr (std::is_same_v<T, DelimiterFieldNode>) {
                    if (concrete.marker.empty()) {
                        throw std::runtime_error("Semantic Error: " + where + ": delimiter marker must not be empty");
                    }
                    if (concrete.marker.size() > 8) {
                        throw std::runtime_error("Semantic Error: " + where + ": delimiter marker is " +
                                                 std::to_string(concrete.marker.size()) + " bytes; at most 8 are supported");
                    }
                    // The scan is unrolled into the program, so the cap also bounds program size and
                    // verifier work; anything beyond one MTU-sized packet would be pointless anyway.
                    if (concrete.max_bytes == 0 || concrete.max_bytes > 1500) {
                        throw std::runtime_error("Semantic Error: " + where + ": delimiter max_bytes must be between 1 and 1500");
                    }
                    r_field.kind = FieldKind::DELIMITER;
                    r_field.is_dynamic = true;
                    r_field.max_size = concrete.max_bytes;
                    r_field.marker = concrete.marker;
                    r_field.trim_whitespace = concrete.trim_whitespace;
                }
                else if constexpr (std::is_same_v<T, VarintFieldNode>) {
                    if (concrete.max_bytes == 0 || concrete.max_bytes > 10) {
                        throw std::runtime_error("Semantic Error: " + where + ": varint max_bytes must be between 1 and 10");
                    }
                    r_field.kind = FieldKind::VARINT;
                    r_field.is_dynamic = true;
                    r_field.max_size = concrete.max_bytes;
                }
            }, field_variant);

            if (r_field.is_dynamic) {
                r_type.is_dynamic = true;
                after_dynamic = true;
            }
            if (!after_dynamic) running_offset += advance;

            r_type.field_map[r_field.name] = r_field;
            r_type.ordered_fields.push_back(r_field);
        }

        recompute_sizes(r_type);
        ctx.type_order.push_back(r_type.name);
        ctx.types[r_type.name] = std::move(r_type);
    }

    // 2. Validate Layout References and bind cross-struct lengths per instance
    std::set<std::string> seen_instances;
    std::map<std::pair<std::string, std::string>, uint32_t> external_caps; // (type, field) -> largest cap
    for (const auto& layout_node : ast.layout) {
        require_c_ident(layout_node.instance_name, "layout instance name");
        if (is_reserved_instance_name(layout_node.instance_name)) {
            throw std::runtime_error("Semantic Error: layout instance name '" + layout_node.instance_name +
                                     "' is reserved by the generated code; pick another name");
        }
        if (!seen_instances.insert(layout_node.instance_name).second) {
            throw std::runtime_error("Semantic Error: Duplicate layout instance name '" + layout_node.instance_name + "'");
        }
        if (layout_node.offset_expr) {
            throw std::runtime_error("Semantic Error: layout instance '" + layout_node.instance_name +
                                     "': layout offsets are not supported yet (instances follow each other directly)");
        }
        auto type_it = ctx.types.find(layout_node.type_ref);
        if (type_it == ctx.types.end()) {
            throw std::runtime_error("Semantic Error: Layout instance '" + layout_node.instance_name +
                                     "' references undefined type '" + layout_node.type_ref + "'");
        }

        ResolvedLayoutInstance r_inst;
        r_inst.instance_name = layout_node.instance_name;
        r_inst.type_ref = layout_node.type_ref;

        if (layout_node.repeat_expr) {
            const std::string where = "layout instance '" + layout_node.instance_name + "'";
            const std::string& expr = *layout_node.repeat_expr;
            if (!type_it->second.is_dynamic) {
                throw std::runtime_error("Semantic Error: " + where + ": repeat is only supported for types with "
                                         "variable-length fields (type '" + layout_node.type_ref + "' is fixed-size)");
            }

            RepeatSpec rs;
            size_t consumed = 0;
            unsigned long constant = 0;
            bool is_number = false;
            try { constant = std::stoul(expr, &consumed, 0); is_number = consumed == expr.size(); } catch (...) {}

            if (is_number) {
                if (layout_node.max_repeat) {
                    throw std::runtime_error("Semantic Error: " + where + ": 'max_repeat' is only for a count read from a "
                                             "field; a constant repeat is its own cap");
                }
                if (expr.find('-') != std::string::npos || constant == 0 || constant > MAX_REPEAT_LIMIT) {
                    throw std::runtime_error("Semantic Error: " + where + ": constant repeat must be between 1 and " +
                                             std::to_string(MAX_REPEAT_LIMIT));
                }
                rs.is_constant = true;
                rs.constant = static_cast<uint32_t>(constant);
                rs.max = rs.constant;
            } else {
                std::string src_inst, src_field;
                if (!split_instance_ref(expr, src_inst, src_field)) {
                    throw std::runtime_error("Semantic Error: " + where + ": repeat '" + expr +
                                             "' must be an integer or 'instance.field'");
                }
                if (!layout_node.max_repeat || *layout_node.max_repeat == 0 || *layout_node.max_repeat > MAX_REPEAT_LIMIT) {
                    throw std::runtime_error("Semantic Error: " + where + ": repeat from '" + expr +
                                             "' needs 'max_repeat' between 1 and " + std::to_string(MAX_REPEAT_LIMIT) +
                                             " (the eBPF verifier requires a hard cap)");
                }
                auto src_it = std::find_if(ctx.layout.begin(), ctx.layout.end(),
                    [&](const ResolvedLayoutInstance& i) { return i.instance_name == src_inst; });
                if (src_it == ctx.layout.end()) {
                    bool exists_later = instance_type.count(src_inst) > 0 && src_inst != layout_node.instance_name;
                    throw std::runtime_error("Semantic Error: " + where + ": count source instance '" + src_inst + "' " +
                                             (exists_later ? "comes later in the layout; it must be parsed before this instance"
                                                           : "does not exist"));
                }
                if (src_it->repeat) {
                    throw std::runtime_error("Semantic Error: " + where + ": count source instance '" + src_inst +
                                             "' is itself repeated; its fields have no single value");
                }
                const ResolvedType& src_type = ctx.types.at(src_it->type_ref);
                auto sf = src_type.field_map.find(src_field);
                if (sf == src_type.field_map.end()) {
                    throw std::runtime_error("Semantic Error: " + where + ": instance '" + src_inst + "' (type '" +
                                             src_type.name + "') has no field '" + src_field + "'");
                }
                if (sf->second.kind != FieldKind::FIXED || sf->second.data_type != DataType::INT ||
                    !is_scalar_int_size(sf->second.max_size)) {
                    throw std::runtime_error("Semantic Error: " + where + ": count source '" + expr +
                                             "' must be a fixed-size integer field (1, 2, 4 or 8 bytes)");
                }
                rs.src_instance = src_inst;
                rs.src_field = src_field;
                rs.max = *layout_node.max_repeat;
            }
            r_inst.repeat = rs;
        }

        for (const auto& f : type_it->second.ordered_fields) {
            if (!f.external_length) continue;
            const std::string where = "length-prefixed field '" + f.name + "' of layout instance '" +
                                      layout_node.instance_name + "'";

            auto sec = ext_sections.find({layout_node.instance_name, f.name});
            if (sec == ext_sections.end()) {
                throw std::runtime_error("Semantic Error: " + where + " (type '" + layout_node.type_ref +
                                         "') has no length source; add an lp_resolutions entry with 'instance: " +
                                         layout_node.instance_name + "'");
            }
            const LengthPrefixedResolution& res = *sec->second;

            std::string src_inst, src_field;
            split_instance_ref(res.length_name, src_inst, src_field); // format already validated in step 0

            if (src_inst == layout_node.instance_name) {
                throw std::runtime_error("Semantic Error: " + where + ": length_name '" + res.length_name +
                                         "' refers to its own instance; use a plain field name for a length in the same type");
            }
            auto src_it = std::find_if(ctx.layout.begin(), ctx.layout.end(),
                [&](const ResolvedLayoutInstance& i) { return i.instance_name == src_inst; });
            if (src_it == ctx.layout.end()) {
                bool exists_later = instance_type.count(src_inst) > 0;
                throw std::runtime_error("Semantic Error: " + where + ": length source instance '" + src_inst + "' " +
                                         (exists_later ? "comes later in the layout; it must be parsed before this instance"
                                                       : "does not exist"));
            }
            if (src_it->repeat) {
                throw std::runtime_error("Semantic Error: " + where + ": length source instance '" + src_inst +
                                         "' is repeated; its fields have no single value");
            }
            const ResolvedType& src_type = ctx.types.at(src_it->type_ref);
            auto sf = src_type.field_map.find(src_field);
            if (sf == src_type.field_map.end()) {
                throw std::runtime_error("Semantic Error: " + where + ": instance '" + src_inst + "' (type '" +
                                         src_type.name + "') has no field '" + src_field + "'");
            }
            if (sf->second.kind != FieldKind::FIXED || sf->second.data_type != DataType::INT ||
                !is_scalar_int_size(sf->second.max_size)) {
                throw std::runtime_error("Semantic Error: " + where + ": length source '" + res.length_name +
                                         "' must be a fixed-size integer field (1, 2, 4 or 8 bytes)");
            }
            if (res.max_bytes == 0) {
                throw std::runtime_error("Semantic Error: " + where + " needs 'max_bytes' > 0 (the eBPF verifier requires a hard cap)");
            }
            if (res.multiplier == 0) {
                throw std::runtime_error("Semantic Error: " + where + ": multiplier must not be 0");
            }

            ExternalLength ext;
            ext.src_instance = src_inst;
            ext.src_field = src_field;
            ext.max_bytes = res.max_bytes;
            ext.multiplier = res.multiplier;
            ext.addend = res.addend;
            r_inst.external_lengths[f.name] = ext;

            uint32_t& cap = external_caps[{layout_node.type_ref, f.name}];
            cap = std::max(cap, res.max_bytes);
        }

        ctx.layout.push_back(std::move(r_inst));
    }

    // Repeated instances get a generated `<name>_n` counter; it must not collide with another instance.
    uint64_t verifier_paths = 1;
    for (const auto& inst : ctx.layout) {
        if (!inst.repeat) continue;
        if (seen_instances.count(inst.instance_name + "_n")) {
            throw std::runtime_error("Semantic Error: layout instance '" + inst.instance_name + "_n' collides with the "
                                     "element counter generated for repeated instance '" + inst.instance_name + "'");
        }
        if (!inst.repeat->is_constant) verifier_paths *= (inst.repeat->max + 1);
    }
    // Each variable-count repetition multiplies the paths the eBPF verifier has to explore.
    if (verifier_paths > 100) {
        std::cerr << "[Analyzer] Warning: repeated instances give up to " << verifier_paths
                  << " parse paths; the kernel verifier may reject the program as too complex "
                     "(lower max_repeat, or check with the loader's -v)\n";
    }

    // 3. Now that every instance's cap is known, finish the size totals of types with cross-struct lengths.
    for (auto& [key, cap] : external_caps) {
        ResolvedType& t = ctx.types.at(key.first);
        t.field_map.at(key.second).max_size = cap;
        for (auto& f : t.ordered_fields) if (f.name == key.second) f.max_size = cap;
        recompute_sizes(t);
    }
    for (const auto& name : ctx.type_order) {
        const ResolvedType& t = ctx.types.at(name);
        // Record offsets in generated code are 16-bit.
        if (t.static_max_size > 65535) {
            throw std::runtime_error("Semantic Error: type '" + t.name + "' can be up to " +
                                     std::to_string(t.static_max_size) + " bytes; the limit is 65535");
        }
    }

    // 4. Validate Observability Filters
    for (const auto& filter_node : ast.filters) {
        std::string layout_inst, field_name;
        std::optional<uint32_t> filter_index;
        if (!split_filter_target(filter_node.target_field, layout_inst, filter_index, field_name)) {
            throw std::runtime_error("Semantic Error: Filter target '" + filter_node.target_field +
                                     "' must use 'layout_instance.field_name' format "
                                     "(or 'layout_instance[N].field_name' for a repeated instance)");
        }

        // Find layout instance
        auto it = std::find_if(ctx.layout.begin(), ctx.layout.end(),
            [&](const ResolvedLayoutInstance& inst) { return inst.instance_name == layout_inst; });

        if (it == ctx.layout.end()) {
            throw std::runtime_error("Semantic Error: Filter references undefined layout instance '" + layout_inst + "'");
        }

        if (it->repeat) {
            if (!filter_index) {
                throw std::runtime_error("Semantic Error: Filter target '" + filter_node.target_field + "': instance '" +
                                         layout_inst + "' is repeated; select an element, e.g. '" + layout_inst + "[0]." +
                                         field_name + "'");
            }
            if (*filter_index >= it->repeat->max) {
                throw std::runtime_error("Semantic Error: Filter target '" + filter_node.target_field + "': index " +
                                         std::to_string(*filter_index) + " is out of range (instance '" + layout_inst +
                                         "' repeats at most " + std::to_string(it->repeat->max) + " time(s))");
            }
        } else if (filter_index) {
            throw std::runtime_error("Semantic Error: Filter target '" + filter_node.target_field + "': instance '" +
                                     layout_inst + "' is not repeated, so it cannot be indexed");
        }

        // Validate field exists in the layout's type
        const ResolvedType& target_type = ctx.types.at(it->type_ref);
        if (target_type.field_map.find(field_name) == target_type.field_map.end()) {
            throw std::runtime_error("Semantic Error: Filter field '" + field_name +
                                     "' not found in type '" + target_type.name + "'");
        }

        ctx.filters.push_back({layout_inst, field_name, filter_node.op, filter_node.value, filter_index});
    }

    return ctx;
}

} // namespace DSLAnalyzer