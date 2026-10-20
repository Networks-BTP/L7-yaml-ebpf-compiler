#pragma once

#include "field_parser.hpp"
#include <yaml-cpp/yaml.h>
#include <stdexcept>

namespace DSLParser {

inline void parse_root_metadata(const YAML::Node& root, ProtocolAST& ast) {
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
}

inline void parse_types_section(const YAML::Node& root, ProtocolAST& ast) {
    if (!root["types"]) return;

    YAML::Node types_node = root["types"];
    if (!types_node.IsMap()) {
        throw std::runtime_error("Parsing Error [Types Section]: 'types' must be a YAML map");
    }

    for (auto it = types_node.begin(); it != types_node.end(); ++it) {
        TypeDefNode type_node;
        type_node.name = it->first.as<std::string>();
        std::string context = "Type '" + type_node.name + "'";
        YAML::Node type_val = it->second;

        if (!type_val.IsMap()) {
            throw std::runtime_error("Parsing Error [" + context + "]: Definition must be a YAML map");
        }

        type_node.static_size = get_optional_field<uint32_t>(type_val, "size");

        if (type_val["fields"]) {
            YAML::Node fields_node = type_val["fields"];
            if (fields_node.IsMap()) {
                for (auto fit = fields_node.begin(); fit != fields_node.end(); ++fit) {
                    type_node.fields.push_back(parse_field(fit->first.as<std::string>(), fit->second));
                }
            } else if (fields_node.IsSequence()) {
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

inline void parse_layout_section(const YAML::Node& root, ProtocolAST& ast) {
    if (!root["layout"]) return;

    YAML::Node layout_node = root["layout"];
    if (layout_node.IsMap()) {
        for (auto it = layout_node.begin(); it != layout_node.end(); ++it) {
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

inline void parse_lp_resolutions_section(const YAML::Node& root, ProtocolAST& ast) {
    YAML::Node lp_node = root["length_prefixed_resolutions"] 
                        ? root["length_prefixed_resolutions"] 
                        : root["lp_resolutions"];
    if (!lp_node) return;

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

inline void parse_filters_section(const YAML::Node& root, ProtocolAST& ast) {
    if (!root["filters"]) return;

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

} // namespace DSLParser