#pragma once

#include "../fields/field_base.hpp"
#include <yaml-cpp/yaml.h>
#include <string>
#include <algorithm>
#include <cctype>
#include <optional>
#include <stdexcept>
#include <type_traits>

namespace DSLParser {

// ============================================================================
// ParserHelper: Centralized Utility Class for YAML Parsing & Type Conversions
// ============================================================================
class ParserHelper {
public:
    /// Strips leading and trailing whitespace characters (\t, \n, \r, space)
    static std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\n\r");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\n\r");
        return str.substr(first, (last - first + 1));
    }

    /// Converts an ASCII string to lower-case for case-insensitive keyword comparisons
    static std::string to_lower(std::string str) {
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return str;
    }

    /**
     * Extracts a required key from a YAML map node.
     * Throws runtime_error if the key does not exist or has a null/empty assignment.
     * Note: Non-empty whitespace characters (like delimiter marker "\n") are preserved.
     */
    template <typename T = std::string>
    static T get_required(const YAML::Node& node, const std::string& key, const std::string& context) {
        if (!node[key]) {
            throw std::runtime_error("Parsing Error [" + context + "]: Missing required key '" + key + "'");
        }
        if (node[key].IsNull() || (node[key].IsScalar() && node[key].as<std::string>().empty())) {
            throw std::runtime_error("Parsing Error [" + context + "]: Key '" + key + "' is present but has no value assigned");
        }
        try {
            return node[key].as<T>();
        } catch (const YAML::Exception& e) {
            throw std::runtime_error("Parsing Error [" + context + "]: Failed to parse value for key '" + key + "' (" + e.what() + ")");
        }
    }

    /**
     * Extracts an optional key from a YAML map node.
     * Returns std::nullopt if the key does not exist or is null.
     */
    template <typename T>
    static std::optional<T> get_optional(const YAML::Node& node, const std::string& key) {
        if (node[key] && !node[key].IsNull()) {
            if constexpr (std::is_same_v<T, std::string>) {
                std::string val = node[key].as<std::string>();
                if (!val.empty()) return val;
            } else {
                return node[key].as<T>();
            }
        }
        return std::nullopt;
    }

    /**
     * Parses DataType string into DataType struct.
     * Handles primitive names ("int", "string", "bytes", "float", "bool")
     * and user-defined custom type names (marked as DataType::CUSTOM).
     */
    static DataType parse_data_type(const std::string& type_str, DataType::Primitive default_type = DataType::INT) {
        if (type_str.empty()) {
            return DataType{default_type, ""};
        }

        std::string s = to_lower(trim(type_str));
        if (s == "int" || s == "integer") return DataType{DataType::INT, ""};
        if (s == "string" || s == "str") return DataType{DataType::STRING, ""};
        if (s == "bytes" || s == "byte" || s == "raw") return DataType{DataType::BYTES, ""};
        if (s == "float" || s == "double") return DataType{DataType::FLOAT, ""};
        if (s == "bool" || s == "boolean") return DataType{DataType::BOOLEAN, ""};

        // If not a built-in primitive, it represents a user-defined custom type reference
        DataType dt;
        dt.primitive = DataType::CUSTOM;
        dt.custom_type_name = trim(type_str); // Preserve casing for struct lookup
        return dt;
    }

    /**
     * Converts comparison operators into FilterOp enum values.
     */
    static FilterOp parse_filter_op(const std::string& op_str, const std::string& context) {
        std::string s = trim(op_str);
        if (s == "==" || s == "EQUAL" || s == "eq") return FilterOp::EQUAL;
        if (s == "!=" || s == "NOT_EQUAL" || s == "ne") return FilterOp::NOT_EQUAL;
        if (s == ">"  || s == "GREATER_THAN" || s == "gt") return FilterOp::GREATER_THAN;
        if (s == "<"  || s == "LESS_THAN" || s == "lt") return FilterOp::LESS_THAN;
        throw std::runtime_error("Parsing Error [" + context + "]: Unknown FilterOp '" + op_str + "'");
    }
};

// ============================================================================
// Compatibility Forwarding Wrappers
// ============================================================================

inline std::string trim(const std::string& str) {
    return ParserHelper::trim(str);
}

inline std::string to_lower(std::string str) {
    return ParserHelper::to_lower(str);
}

template <typename T = std::string>
inline T get_required_field(const YAML::Node& node, const std::string& key, const std::string& context) {
    return ParserHelper::get_required<T>(node, key, context);
}

template <typename T>
inline std::optional<T> get_optional_field(const YAML::Node& node, const std::string& key) {
    return ParserHelper::get_optional<T>(node, key);
}

} // namespace DSLParser
