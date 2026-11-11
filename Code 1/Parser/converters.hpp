#pragma once

#include "helpers.hpp"

namespace DSLParser {

inline DataType parse_data_type(const std::string& type_str, DataType::Primitive default_type = DataType::INT) {
    return ParserHelper::parse_data_type(type_str, default_type);
}

inline FilterOp parse_filter_op(const std::string& op_str, const std::string& context) {
    return ParserHelper::parse_filter_op(op_str, context);
}

} // namespace DSLParser
