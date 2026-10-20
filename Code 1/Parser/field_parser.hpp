#pragma once

#include "converters.hpp"
#include <string>
#include <stdexcept>

namespace DSLParser {

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

} // namespace DSLParser