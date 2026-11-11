#pragma once

#include "ast.hpp"
#include "helpers.hpp"
#include <yaml-cpp/yaml.h>
#include <stdexcept>

namespace DSLParser {

// ============================================================================
// SectionParser: Modular Handlers for Each YAML Section
// ============================================================================
class SectionParser {
public:
    /**
     * Parses root metadata (protocol name, transport layer, default port).
     *
     * Validations:
     *   - Requires either 'protocol' or 'name' string key.
     *   - 'transport' defaults to empty if not specified.
     *   - 'port' defaults to 0 if not specified.
     */
    static void parse_root_metadata(const YAML::Node& root, ProtocolAST& ast) {
        if (root["protocol"]) {
            ast.protocol_name = ParserHelper::get_required<std::string>(root, "protocol", "Root Metadata");
        } else if (root["name"]) {
            ast.protocol_name = ParserHelper::get_required<std::string>(root, "name", "Root Metadata");
        } else {
            throw std::runtime_error("Parsing Error [Root Metadata]: Missing required key 'protocol' or 'name'");
        }

        if (root["transport"]) {
            ast.transport = ParserHelper::get_required<std::string>(root, "transport", "Root Metadata");
        }

        if (root["port"]) {
            ast.default_port = ParserHelper::get_required<uint16_t>(root, "port", "Root Metadata");
        }
    }

    /**
     * Parses the 'types' section describing packet headers and composite structs.
     *
     * Structure:
     *   types:
     *     TypeName:
     *       size: <optional static byte bound>
     *       fields:
     *         field_name: { type: ..., ... }    # Map format
     *         # OR
     *         - name: field_name, type: ...     # Sequence format
     *
     * In sequence format, if 'name' is omitted, it defaults to the 'type' value.
     */
    static void parse_types_section(const YAML::Node& root, ProtocolAST& ast) {
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

            type_node.static_size = ParserHelper::get_optional<uint32_t>(type_val, "size");

            if (type_val["fields"]) {
                YAML::Node fields_node = type_val["fields"];

                // Format 1: Map representation: `field_name: { type: ... }`
                if (fields_node.IsMap()) {
                    for (auto fit = fields_node.begin(); fit != fields_node.end(); ++fit) {
                        std::string fname = fit->first.as<std::string>();
                        type_node.fields.push_back(FieldRegistry::instance().parse(fname, fit->second));
                    }
                }
                // Format 2: Sequence representation: `- name: foo, type: ...`
                else if (fields_node.IsSequence()) {
                    for (const auto& fitem : fields_node) {
                        std::string fname;
                        if (fitem["name"]) {
                            fname = fitem["name"].as<std::string>();
                        } else if (fitem["type"]) {
                            // Default field name to type if 'name' key is omitted in sequence
                            fname = fitem["type"].as<std::string>();
                        } else {
                            throw std::runtime_error("Parsing Error [" + context + " Field Item]: Missing 'name' or 'type'");
                        }
                        type_node.fields.push_back(FieldRegistry::instance().parse(fname, fitem));
                    }
                } else {
                    throw std::runtime_error("Parsing Error [" + context + "]: 'fields' must be a map or a sequence");
                }
            }
            ast.types.push_back(type_node);
        }
    }

    /**
     * Parses the 'layout' section defining on-the-wire header and payload sequence.
     *
     * Supports both:
     *   1. Map format: `instance_name: { type: TypeName, offset: ... }` or `instance_name: TypeName`
     *   2. Sequence format: `- name: instance_name, type: TypeName, offset: ...`
     */
    static void parse_layout_section(const YAML::Node& root, ProtocolAST& ast) {
        if (!root["layout"]) return;

        YAML::Node layout_node = root["layout"];

        // Map layout format
        if (layout_node.IsMap()) {
            for (auto it = layout_node.begin(); it != layout_node.end(); ++it) {
                LayoutNode lnode;
                lnode.instance_name = it->first.as<std::string>();
                std::string context = "Layout Instance '" + lnode.instance_name + "'";
                YAML::Node lval = it->second;

                if (lval.IsMap()) {
                    lnode.type_ref = ParserHelper::get_required<std::string>(lval, "type", context);
                    lnode.offset_expr = ParserHelper::get_optional<std::string>(lval, "offset");
                } else if (lval.IsScalar()) {
                    lnode.type_ref = lval.as<std::string>();
                }
                ast.layout.push_back(lnode);
            }
        }
        // Sequence layout format
        else if (layout_node.IsSequence()) {
            for (const auto& item : layout_node) {
                LayoutNode lnode;
                std::string context = "Layout Sequence Item";
                lnode.instance_name = ParserHelper::get_required<std::string>(item, "name", context);
                lnode.type_ref = ParserHelper::get_required<std::string>(item, "type", context + " '" + lnode.instance_name + "'");
                lnode.offset_expr = ParserHelper::get_optional<std::string>(item, "offset");
                ast.layout.push_back(lnode);
            }
        } else {
            throw std::runtime_error("Parsing Error [Layout Section]: 'layout' must be a map or a sequence");
        }
    }

    /**
     * Parses length-prefixed dynamic field resolutions.
     * Binds a length field (e.g. `hdr.len`) to a target variable-length payload.
     */
    static void parse_lp_resolutions_section(const YAML::Node& root, ProtocolAST& ast) {
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
            res.field_name = ParserHelper::get_required<std::string>(item, "field_name", context);
            res.length_name = ParserHelper::get_required<std::string>(item, "length_name", context);
            res.max_bytes = ParserHelper::get_required<uint32_t>(item, "max_bytes", context + " for '" + res.field_name + "'");
            res.multiplier = ParserHelper::get_optional<uint32_t>(item, "multiplier").value_or(1);
            res.addend = ParserHelper::get_optional<int32_t>(item, "addend").value_or(0);

            ast.LPresolution.push_back(res);
        }
    }

    /**
     * Parses observability filter predicates.
     * Checks both root `filters` and `observability.filters` locations.
     */
    static void parse_filters_section(const YAML::Node& root, ProtocolAST& ast) {
        YAML::Node filter_node;
        if (root["filters"]) {
            filter_node = root["filters"];
        } else if (root["observability"] && root["observability"]["filters"]) {
            filter_node = root["observability"]["filters"];
        } else {
            return;
        }

        if (!filter_node.IsSequence()) {
            throw std::runtime_error("Parsing Error [Filters Section]: 'filters' must be a YAML sequence");
        }

        for (size_t i = 0; i < filter_node.size(); ++i) {
            std::string context = "Filter Item #" + std::to_string(i + 1);
            YAML::Node item = filter_node[i];

            FilterNode fnode;
            if (item["target_field"]) {
                fnode.target_field = ParserHelper::get_required<std::string>(item, "target_field", context);
            } else {
                fnode.target_field = ParserHelper::get_required<std::string>(item, "field", context);
            }

            std::string raw_op = ParserHelper::get_required<std::string>(item, "op", context + " for field '" + fnode.target_field + "'");
            fnode.op = ParserHelper::parse_filter_op(raw_op, context);
            fnode.value = ParserHelper::get_required<std::string>(item, "value", context + " for field '" + fnode.target_field + "'");

            ast.filters.push_back(fnode);
        }
    }
};

// ============================================================================
// Compatibility Forwarding Wrappers
// ============================================================================

inline void parse_root_metadata(const YAML::Node& root, ProtocolAST& ast) {
    SectionParser::parse_root_metadata(root, ast);
}

inline void parse_types_section(const YAML::Node& root, ProtocolAST& ast) {
    SectionParser::parse_types_section(root, ast);
}

inline void parse_layout_section(const YAML::Node& root, ProtocolAST& ast) {
    SectionParser::parse_layout_section(root, ast);
}

inline void parse_lp_resolutions_section(const YAML::Node& root, ProtocolAST& ast) {
    SectionParser::parse_lp_resolutions_section(root, ast);
}

inline void parse_filters_section(const YAML::Node& root, ProtocolAST& ast) {
    SectionParser::parse_filters_section(root, ast);
}

} // namespace DSLParser
