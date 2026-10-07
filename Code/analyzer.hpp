#pragma once

#include "ast.hpp"
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <iostream>

namespace DSLAnalyzer {

// Helper: Extract FieldBase from variant
inline const FieldBase& get_field_base(const FieldNode& node) {
    return std::visit([](const auto& f) -> const FieldBase& {
        return static_cast<const FieldBase&>(f);
    }, node);
}

// --- Resolved Symbol Table Data Structures ---

struct ResolvedField {
    std::string name;
    DataType data_type;
    uint32_t offset{0};       // Statically calculated byte offset (if applicable)
    uint32_t max_size{0};     // Maximum byte size (critical for verifier bounds)
    bool is_dynamic{false};   // True if size is variable (delimiter, varint, etc.)
};

struct ResolvedType {
    std::string name;
    uint32_t static_min_size{0}; // Minimum guaranteed size
    uint32_t static_max_size{0}; // Maximum possible size
    bool is_dynamic{false};      // True if it contains variable-length fields
    std::unordered_map<std::string, ResolvedField> field_map;
    std::vector<ResolvedField> ordered_fields;
};

struct ResolvedLayoutInstance {
    std::string instance_name;
    std::string type_ref;
};

struct ResolvedFilter {
    std::string layout_instance;
    std::string field_name;
    FilterOp op;
    std::string value;
};

struct ResolvedContext {
    std::string protocol_name;
    std::string transport;
    uint16_t port;
    std::unordered_map<std::string, ResolvedType> types;
    std::vector<ResolvedLayoutInstance> layout;
    std::vector<ResolvedFilter> filters;
};

// --- Analysis Logic ---

inline ResolvedContext analyze(const ProtocolAST& ast) {
    ResolvedContext ctx;
    ctx.protocol_name = ast.protocol_name;
    ctx.transport = ast.transport;
    ctx.port = ast.default_port;

    // 1. Resolve Types and Calculate Offsets
    for (const auto& type_node : ast.types) {
        ResolvedType r_type;
        r_type.name = type_node.name;
        uint32_t current_offset = 0;

        for (const auto& field_variant : type_node.fields) {
            const FieldBase& base = get_field_base(field_variant);
            ResolvedField r_field;
            r_field.name = base.name;
            r_field.data_type = base.data_type;

            // Handle explicit offset expressions if provided (skipping complex math parsing for this MVP)
            if (base.offset_expr) {
                try {
                    current_offset = std::stoul(*base.offset_expr);
                } catch (...) {
                    // In a full compiler, you'd evaluate the math expression here
                }
            }
            r_field.offset = current_offset;

            // Determine size and dynamism based on concrete field type
            std::visit([&](auto&& concrete_field) {
                using T = std::decay_t<decltype(concrete_field)>;

                if constexpr (std::is_same_v<T, FixedFieldNode>) {
                    r_field.max_size = concrete_field.size_bytes;
                    r_field.is_dynamic = false;
                    current_offset += concrete_field.size_bytes;
                } 
                else if constexpr (std::is_same_v<T, DelimiterFieldNode>) {
                    r_field.max_size = concrete_field.max_bytes;
                    r_field.is_dynamic = true;
                    r_type.is_dynamic = true;
                    // Dynamic fields mean static offsets break for subsequent fields
                }
                else if constexpr (std::is_same_v<T, VarintFieldNode>) {
                    r_field.max_size = concrete_field.max_bytes;
                    r_field.is_dynamic = true;
                    r_type.is_dynamic = true;
                }
                else if constexpr (std::is_same_v<T, LengthPrefixedFieldNode>) {
                    r_field.is_dynamic = true;
                    r_type.is_dynamic = true;
                    // The max_size will be resolved during LP resolution check below
                }
            }, field_variant);

            r_type.static_min_size = r_type.is_dynamic ? r_type.static_min_size : current_offset;
            r_type.static_max_size += r_field.max_size;

            if (r_type.field_map.find(r_field.name) != r_type.field_map.end()) {
                throw std::runtime_error("Semantic Error: Duplicate field name '" + r_field.name + "' in type '" + r_type.name + "'");
            }

            r_type.field_map[r_field.name] = r_field;
            r_type.ordered_fields.push_back(r_field);
        }

        ctx.types[r_type.name] = r_type;
    }

    // 2. Validate Layout References
    for (const auto& layout_node : ast.layout) {
        if (ctx.types.find(layout_node.type_ref) == ctx.types.end()) {
            throw std::runtime_error("Semantic Error: Layout instance '" + layout_node.instance_name + 
                                     "' references undefined type '" + layout_node.type_ref + "'");
        }
        ctx.layout.push_back({layout_node.instance_name, layout_node.type_ref});
    }

    // 3. Validate LP Resolutions
    for (const auto& lp_res : ast.LPresolution) {
        // Find which type contains the length_name and field_name
        bool resolved = false;
        for (auto& [type_name, r_type] : ctx.types) {
            if (r_type.field_map.count(lp_res.field_name) && r_type.field_map.count(lp_res.length_name)) {
                r_type.field_map[lp_res.field_name].max_size = lp_res.max_bytes;
                resolved = true;
                break;
            }
        }
        if (!resolved) {
            throw std::runtime_error("Semantic Error: LP Resolution fields '" + lp_res.field_name + 
                                     "' or '" + lp_res.length_name + "' not found in the same type definition");
        }
    }

    // 4. Validate Observability Filters
    for (const auto& filter_node : ast.filters) {
        size_t dot_pos = filter_node.target_field.find('.');
        if (dot_pos == std::string::npos) {
            throw std::runtime_error("Semantic Error: Filter target '" + filter_node.target_field + 
                                     "' must use 'layout_instance.field_name' format");
        }

        std::string layout_inst = filter_node.target_field.substr(0, dot_pos);
        std::string field_name = filter_node.target_field.substr(dot_pos + 1);

        // Find layout instance
        auto it = std::find_if(ctx.layout.begin(), ctx.layout.end(), 
            [&](const ResolvedLayoutInstance& inst) { return inst.instance_name == layout_inst; });
        
        if (it == ctx.layout.end()) {
            throw std::runtime_error("Semantic Error: Filter references undefined layout instance '" + layout_inst + "'");
        }

        // Validate field exists in the layout's type
        const ResolvedType& target_type = ctx.types[it->type_ref];
        if (target_type.field_map.find(field_name) == target_type.field_map.end()) {
            throw std::runtime_error("Semantic Error: Filter field '" + field_name + 
                                     "' not found in type '" + target_type.name + "'");
        }

        ctx.filters.push_back({layout_inst, field_name, filter_node.op, filter_node.value});
    }

    return ctx;
}

} // namespace DSLAnalyzer