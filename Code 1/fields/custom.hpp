#pragma once

#include "field_base.hpp"
#include "../Parser/helpers.hpp"
#include <yaml-cpp/yaml.h>
#include <memory>
#include <stdexcept>

// ============================================================================
// CustomField: Nested or Recursive User-Defined Struct Type Field
// ============================================================================
class CustomField : public FieldBase {
public:
    std::string custom_type_name_val;

    std::string type_name() const override { return "custom"; }
    bool is_dynamic() const override { return false; /* Dynamism resolved when inspecting target type */ }
    bool is_recursive() const override { return true; }
    std::string recursive_type_name() const override {
        return !custom_type_name_val.empty() ? custom_type_name_val : data_type.custom_type_name;
    }

    std::shared_ptr<FieldBase> clone() const override {
        return std::make_shared<CustomField>(*this);
    }

    // ------------------------------------------------------------------------
    // 1. Modular Parser Step
    // ------------------------------------------------------------------------
    /**
     * Parses a nested or recursive custom struct field from a YAML map node.
     *
     * Resolves the custom struct type name from:
     *   1. Explicit argument `explicit_type` (if provided)
     *   2. `data_type` key in YAML
     *   3. `type` key in YAML (when referencing a custom type name)
     */
    static std::shared_ptr<CustomField> parse(const std::string& field_name,
                                              const YAML::Node& node,
                                              const std::string& explicit_type = "") {
        auto field = std::make_shared<CustomField>();
        field->name = field_name;
        field->offset_expr = DSLParser::ParserHelper::get_optional<std::string>(node, "offset");

        std::string type_name_val = explicit_type;
        if (type_name_val.empty()) {
            type_name_val = DSLParser::ParserHelper::get_optional<std::string>(node, "data_type").value_or("");
        }
        if (type_name_val.empty()) {
            type_name_val = DSLParser::ParserHelper::get_optional<std::string>(node, "type").value_or("");
        }

        field->custom_type_name_val = DSLParser::ParserHelper::trim(type_name_val);
        field->data_type.primitive = DataType::CUSTOM;
        field->data_type.custom_type_name = field->custom_type_name_val;

        return field;
    }

    // ------------------------------------------------------------------------
    // 2. Modular Analyzer Step
    // ------------------------------------------------------------------------
    /**
     * Custom fields are composite/recursive containers and are unwrapped into their
     * constituent leaves during traversal.
     */
    ResolvedLeafField create_leaf(const FieldAnalyzeContext& /*ctx*/) const override {
        throw std::runtime_error("Analyzer Error: create_leaf called on non-leaf composite field '" +
                                 name + "' (type: " + recursive_type_name() + ")");
    }
};

// Typedef for backward compatibility
using CustomFieldNode = CustomField;

namespace DSLParser {
inline std::shared_ptr<FieldBase> parse_custom_field(const std::string& name, const YAML::Node& node, const std::string& type = "") {
    return CustomField::parse(name, node, type);
}
} // namespace DSLParser
