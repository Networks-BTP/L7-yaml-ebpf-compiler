#pragma once

#include "ast.hpp"
#include <yaml-cpp/yaml.h>
#include <stdexcept>
#include <string>
#include <algorithm>
#include <cctype>

namespace DSLParser {

// Helper: Trim string
inline std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

// Helper: Case-insensitive string comparison
inline std::string to_lower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c){ return std::tolower(c); });
    return str;
}

// Central Validation Helper: Checks both key presence AND value availability
template <typename T = std::string>
inline T get_required_field(const YAML::Node& node, const std::string& key, const std::string& context) {
    if (!node[key]) {
        throw std::runtime_error("Parsing Error [" + context + "]: Missing required key '" + key + "'");
    }
    
    // Check if node exists but has no scalar value (e.g., `key:` or `key: null`)
    if (node[key].IsNull() || (node[key].IsScalar() && trim(node[key].as<std::string>()).empty())) {
        throw std::runtime_error("Parsing Error [" + context + "]: Key '" + key + "' is present but has no value assigned");
    }

    try {
        return node[key].as<T>();
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("Parsing Error [" + context + "]: Failed to parse value for key '" + key + "' (" + e.what() + ")");
    }
}

// Helper to safely extract optional values
template <typename T>
inline std::optional<T> get_optional_field(const YAML::Node& node, const std::string& key) {
    if (node[key] && !node[key].IsNull()) {
        if constexpr (std::is_same_v<T, std::string>) {
            std::string val = trim(node[key].as<std::string>());
            if (!val.empty()) return val;
        } else {
            return node[key].as<T>();
        }
    }
    return std::nullopt;
}

// Enum Conversions
inline DataType parse_data_type(const std::string& type_str, DataType default_type = DataType::INT) {
    std::string s = to_lower(trim(type_str));
    if (s == "int" || s == "integer") return DataType::INT;
    if (s == "string" || s == "str") return DataType::STRING;
    if (s == "bytes" || s == "byte" || s == "raw") return DataType::BYTES;
    if (s == "float" || s == "double") return DataType::FLOAT;
    if (s == "bool" || s == "boolean") return DataType::BOOLEAN;
    return default_type;
}

inline FilterOp parse_filter_op(const std::string& op_str, const std::string& context) {
    std::string s = trim(op_str);
    if (s == "==" || s == "EQUAL" || s == "eq") return FilterOp::EQUAL;
    if (s == "!=" || s == "NOT_EQUAL" || s == "ne") return FilterOp::NOT_EQUAL;
    if (s == ">"  || s == "GREATER_THAN" || s == "gt") return FilterOp::GREATER_THAN;
    if (s == "<"  || s == "LESS_THAN" || s == "lt") return FilterOp::LESS_THAN;
    throw std::runtime_error("Parsing Error [" + context + "]: Unknown FilterOp '" + op_str + "'");
}

// Parse Individual Field Nodes
inline FieldNode parse_field(const std::string& field_name, const YAML::Node& node) {
    std::string context = "Field '" + field_name + "'";

    if (!node.IsMap()) {
        throw std::runtime_error("Parsing Error [" + context + "]: Field definition must be a YAML map");
    }

    std::string prim_type = to_lower(get_required_field<std::string>(node, "type", context));
    std::optional<std::string> offset_expr = get_optional_field<std::string>(node, "offset");
    std::string raw_data_type = get_optional_field<std::string>(node, "data_type").value_or("");

    if (prim_type == "fixed") {
        FixedFieldNode field;
        field.name = field_name;
        field.offset_expr = offset_expr;
        field.data_type = parse_data_type(raw_data_type, DataType::INT);
        field.size_bytes = get_optional_field<uint32_t>(node, "size").value_or(4);
        return field;
    } 
    else if (prim_type == "length_prefixed" || prim_type == "length_prefixed_field") {
        LengthPrefixedFieldNode field;
        field.name = field_name;
        field.offset_expr = offset_expr;
        field.data_type = parse_data_type(raw_data_type, DataType::BYTES);
        return field;
    } 
    else if (prim_type == "delimiter") {
        DelimiterFieldNode field;
        field.name = field_name;
        field.offset_expr = offset_expr;
        field.data_type = parse_data_type(raw_data_type, DataType::STRING);
        field.marker = get_required_field<std::string>(node, "marker", context);
        field.max_bytes = get_optional_field<uint32_t>(node, "max_bytes").value_or(128);
        field.trim_whitespace = get_optional_field<bool>(node, "trim_whitespace").value_or(false);
        return field;
    } 
    else if (prim_type == "varint") {
        VarintFieldNode field;
        field.name = field_name;
        field.offset_expr = offset_expr;
        field.data_type = parse_data_type(raw_data_type, DataType::INT);
        field.max_bytes = get_optional_field<uint32_t>(node, "max_bytes").value_or(5);
        return field;
    }

    throw std::runtime_error("Parsing Error [" + context + "]: Unsupported primitive type '" + prim_type + "'");
}

// Main Protocol AST Parser Pass
inline ProtocolAST parse_yaml(const std::string& yaml_content) {
    YAML::Node root = YAML::Load(yaml_content);
    ProtocolAST ast;

    // 1. Root Meta Information
    if (root["protocol"]) {
        ast.protocol_name = get_required_field<std::string>(root, "protocol", "Root Metadata");
    } else if (root["name"]) {
        ast.protocol_name = get_required_field<std::string>(root, "name", "Root Metadata");
    } else {
        throw std::runtime_error("Parsing Error [Root Metadata]: Missing required key 'protocol' or 'name'");
    }

    if (root["transport"]) {
        ast.transport = get_required_field<std::string>(root, "transport", "Root Metadata");
    }

    if (root["port"]) {
        ast.default_port = get_required_field<uint16_t>(root, "port", "Root Metadata");
    }

    // 2. Types Section
    if (root["types"]) {
        if (!root["types"].IsMap()) {
            throw std::runtime_error("Parsing Error [Types Section]: 'types' must be a YAML map");
        }

        for (YAML::const_iterator it = root["types"].begin(); it != root["types"].end(); ++it) {
            TypeDefNode type_node;
            type_node.name = it->first.as<std::string>();
            std::string context = "Type '" + type_node.name + "'";
            YAML::Node type_val = it->second;

            if (!type_val.IsMap()) {
                throw std::runtime_error("Parsing Error [" + context + "]: Definition must be a YAML map");
            }

            type_node.static_size = get_optional_field<uint32_t>(type_val, "static_size");

            if (type_val["fields"]) {
                YAML::Node fields_node = type_val["fields"];
                
                // Map format: field_name: { type: ... }
                if (fields_node.IsMap()) {
                    for (YAML::const_iterator fit = fields_node.begin(); fit != fields_node.end(); ++fit) {
                        std::string fname = fit->first.as<std::string>();
                        type_node.fields.push_back(parse_field(fname, fit->second));
                    }
                } 
                // Sequence format: - name: foo, type: ...
                else if (fields_node.IsSequence()) {
                    for (const auto& fitem : fields_node) {
                        std::string fname = get_required_field<std::string>(fitem, "name", context + " Field Item");
                        type_node.fields.push_back(parse_field(fname, fitem));
                    }
                } else {
                    throw std::runtime_error("Parsing Error [" + context + "]: 'fields' must be a map or a sequence");
                }
            }
            ast.types.push_back(type_node);
        }
    }

    // 3. Layout Section
    if (root["layout"]) {
        YAML::Node layout_node = root["layout"];

        if (layout_node.IsMap()) {
            for (YAML::const_iterator it = layout_node.begin(); it != layout_node.end(); ++it) {
                LayoutNode lnode;
                lnode.instance_name = it->first.as<std::string>();
                std::string context = "Layout Instance '" + lnode.instance_name + "'";
                YAML::Node lval = it->second;

                if (lval.IsMap()) {
                    lnode.type_ref = get_required_field<std::string>(lval, "type", context);
                    lnode.offset_expr = get_optional_field<std::string>(lval, "offset");
                } else if (lval.IsScalar()) {
                    lnode.type_ref = get_required_field<std::string>(layout_node, lnode.instance_name, context);
                }
                ast.layout.push_back(lnode);
            }
        } else if (layout_node.IsSequence()) {
            for (const auto& item : layout_node) {
                LayoutNode lnode;
                std::string context = "Layout Sequence Item";
                lnode.instance_name = get_required_field<std::string>(item, "name", context);
                lnode.type_ref = get_required_field<std::string>(item, "type", context + " '" + lnode.instance_name + "'");
                lnode.offset_expr = get_optional_field<std::string>(item, "offset");
                ast.layout.push_back(lnode);
            }
        } else {
            throw std::runtime_error("Parsing Error [Layout Section]: 'layout' must be a map or a sequence");
        }
    }

    // 4. Length-Prefixed Field Resolutions
    if (root["length_prefixed_resolutions"] || root["lp_resolutions"]) {
        YAML::Node lp_node = root["length_prefixed_resolutions"] 
                            ? root["length_prefixed_resolutions"] 
                            : root["lp_resolutions"];

        if (!lp_node.IsSequence()) {
            throw std::runtime_error("Parsing Error [LP Resolutions]: Section must be a YAML sequence");
        }

        for (size_t i = 0; i < lp_node.size(); ++i) {
            std::string context = "LP Resolution Item #" + std::to_string(i + 1);
            YAML::Node item = lp_node[i];

            LengthPrefixedResolution res;
            res.field_name = get_required_field<std::string>(item, "field_name", context);
            res.length_name = get_required_field<std::string>(item, "length_name", context);
            res.max_bytes = get_required_field<uint32_t>(item, "max_bytes", context + " for '" + res.field_name + "'");

            res.multiplier = get_optional_field<uint32_t>(item, "multiplier").value_or(1);
            res.addend = get_optional_field<int32_t>(item, "addend").value_or(0);

            ast.LPresolution.push_back(res);
        }
    }

    // 5. Filters Section
    if (root["filters"]) {
        YAML::Node filter_node = root["filters"];
        if (!filter_node.IsSequence()) {
            throw std::runtime_error("Parsing Error [Filters Section]: 'filters' must be a YAML sequence");
        }

        for (size_t i = 0; i < filter_node.size(); ++i) {
            std::string context = "Filter Item #" + std::to_string(i + 1);
            YAML::Node item = filter_node[i];

            FilterNode fnode;
            if (item["target_field"]) {
                fnode.target_field = get_required_field<std::string>(item, "target_field", context);
            } else {
                fnode.target_field = get_required_field<std::string>(item, "field", context);
            }

            std::string raw_op = get_required_field<std::string>(item, "op", context + " for field '" + fnode.target_field + "'");
            fnode.op = parse_filter_op(raw_op, context);
            fnode.value = get_required_field<std::string>(item, "value", context + " for field '" + fnode.target_field + "'");

            ast.filters.push_back(fnode);
        }
    }

    return ast;
}

} // namespace DSLParser