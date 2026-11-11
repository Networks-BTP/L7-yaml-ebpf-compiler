#pragma once

#include "field_base.hpp"
#include "fixed.hpp"
#include "delimiter.hpp"
#include "varint.hpp"
#include "length_prefixed.hpp"
#include "custom.hpp"

#include <functional>
#include <unordered_map>
#include <string>
#include <memory>
#include <yaml-cpp/yaml.h>

namespace DSLParser {

using FieldParserFn = std::function<std::shared_ptr<FieldBase>(const std::string& field_name,
                                                               const YAML::Node& node)>;

// ============================================================================
// FieldRegistry: Modular Registry & Factory for Field Types
// ============================================================================
/// Enables adding or removing field types modularly without modifying the Parser
/// or Analyzer source code. Any new field type can be added by registering its
/// parsing function with FieldRegistry::instance().register_type(...).
class FieldRegistry {
public:
    /// Singleton accessor ensuring safe, single-point registration
    static FieldRegistry& instance() {
        static FieldRegistry reg;
        return reg;
    }

    /// Registers a parser factory function for a given field type identifier
    void register_type(const std::string& type_name, FieldParserFn parser) {
        parsers_[ParserHelper::to_lower(type_name)] = parser;
    }

    /// Checks if a parser factory exists for the specified type name
    bool has_type(const std::string& type_name) const {
        return parsers_.find(ParserHelper::to_lower(type_name)) != parsers_.end();
    }

    /**
     * Parses a field node from a YAML map.
     *
     * Resolution order:
     *   1. If `data_type` is specified as a custom struct type, constructs a CustomField.
     *   2. If `type` matches a registered primitive/alias, invokes its parser.
     *   3. Otherwise, treats `type` as a user-defined custom/recursive struct type.
     */
    std::shared_ptr<FieldBase> parse(const std::string& field_name, const YAML::Node& node) const {
        std::string context = "Field '" + field_name + "'";

        if (!node.IsMap()) {
            throw std::runtime_error("Parsing Error [" + context + "]: Field definition must be a YAML map");
        }

        std::string raw_type = ParserHelper::get_required<std::string>(node, "type", context);
        std::string low_type = ParserHelper::to_lower(ParserHelper::trim(raw_type));

        // 1. Check if data_type points to a custom/recursive struct type
        std::string raw_data_type = ParserHelper::get_optional<std::string>(node, "data_type").value_or("");
        if (!raw_data_type.empty()) {
            DataType dt = ParserHelper::parse_data_type(raw_data_type);
            if (dt.is_custom() && (low_type == "custom" || low_type == "fixed")) {
                return CustomField::parse(field_name, node, dt.custom_type_name);
            }
        }

        // 2. Look up registered parser function
        auto it = parsers_.find(low_type);
        if (it != parsers_.end()) {
            return it->second(field_name, node);
        }

        // 3. Fallback: treat unregistered type string as a user-defined custom struct reference
        return CustomField::parse(field_name, node, ParserHelper::trim(raw_type));
    }

private:
    FieldRegistry() {
        register_builtins();
    }

    /// Registers built-in primitives and standard network scalar aliases
    void register_builtins() {
        // Built-in field kinds
        register_type("fixed", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 4);
        });
        register_type("delimiter", DelimiterField::parse);
        register_type("varint", VarintField::parse);
        register_type("length_prefixed", LengthPrefixedField::parse);
        register_type("length_prefixed_field", LengthPrefixedField::parse);
        register_type("custom", [](const std::string& name, const YAML::Node& n) {
            return CustomField::parse(name, n);
        });

        // Common network integer aliases
        register_type("u8", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 1);
        });
        register_type("uint8", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 1);
        });
        register_type("u16", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 2);
        });
        register_type("uint16", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 2);
        });
        register_type("u24", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 3);
        });
        register_type("u32", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 4);
        });
        register_type("uint32", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 4);
        });
        register_type("ipv4", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 4);
        });
        register_type("u64", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 8);
        });
        register_type("uint64", [](const std::string& name, const YAML::Node& n) {
            return FixedField::parse(name, n, 8);
        });
    }

    std::unordered_map<std::string, FieldParserFn> parsers_;
};

} // namespace DSLParser
