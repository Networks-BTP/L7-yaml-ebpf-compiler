#pragma once

#include "ast.hpp"
#include "helpers.hpp"
#include <string>
#include <stdexcept>

namespace DSLParser {

inline DataType parse_data_type(const std::string& type_str) {
    if (type_str.empty()) {
        return DataType{DataType::INT, ""};
    }

    std::string s = to_lower(trim(type_str));
    if (s == "int" || s == "integer") return DataType{DataType::INT, ""};
    if (s == "string" || s == "str") return DataType{DataType::STRING, ""};
    if (s == "bytes" || s == "byte" || s == "raw") return DataType{DataType::BYTES, ""};
    if (s == "float" || s == "double") return DataType{DataType::FLOAT, ""};
    if (s == "bool" || s == "boolean") return DataType{DataType::BOOLEAN, ""};

    // If it's not a primitive, it's a user-defined type reference!
    DataType dt;
    dt.primitive = DataType::CUSTOM;
    dt.custom_type_name = trim(type_str); // Preserve case for type lookup
    return dt;
}

inline FilterOp parse_filter_op(const std::string& op_str, const std::string& context) {
    std::string s = trim(op_str);
    if (s == "==" || s == "EQUAL" || s == "eq") return FilterOp::EQUAL;
    if (s == "!=" || s == "NOT_EQUAL" || s == "ne") return FilterOp::NOT_EQUAL;
    if (s == ">"  || s == "GREATER_THAN" || s == "gt") return FilterOp::GREATER_THAN;
    if (s == "<"  || s == "LESS_THAN" || s == "lt") return FilterOp::LESS_THAN;
    throw std::runtime_error("Parsing Error [" + context + "]: Unknown FilterOp '" + op_str + "'");
}

} // namespace DSLParser