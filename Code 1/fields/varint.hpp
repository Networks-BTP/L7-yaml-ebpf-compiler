#pragma once

#include "field_base.hpp"
#include "../Parser/helpers.hpp"
#include <yaml-cpp/yaml.h>
#include <memory>

// ============================================================================
// VarintField: Variable-Length LEB128 Encoded Integer
// ============================================================================
class VarintField : public FieldBase {
public:
    uint32_t max_bytes{5};

    std::string type_name() const override { return "varint"; }
    bool is_dynamic() const override { return true; }
    uint32_t static_size() const override { return 0; }
    uint32_t max_size() const override { return max_bytes; }

    std::shared_ptr<FieldBase> clone() const override {
        return std::make_shared<VarintField>(*this);
    }

    // ------------------------------------------------------------------------
    // 1. Modular Parser Step
    // ------------------------------------------------------------------------
    /**
     * Parses a variable-length integer definition from a YAML map node.
     *
     * Supported YAML keys:
     *   - max_bytes: (Optional) Max encoded length (default 5 for 32-bit uint)
     *   - data_type: (Optional) Target representation (defaults to INT)
     *   - offset: (Optional) Explicit byte offset expression
     */
    static std::shared_ptr<VarintField> parse(const std::string& field_name,
                                              const YAML::Node& node) {
        auto field = std::make_shared<VarintField>();
        field->name = field_name;
        field->offset_expr = DSLParser::ParserHelper::get_optional<std::string>(node, "offset");

        std::string raw_data_type = DSLParser::ParserHelper::get_optional<std::string>(node, "data_type").value_or("");
        field->data_type = DSLParser::ParserHelper::parse_data_type(raw_data_type, DataType::INT);
        field->max_bytes = DSLParser::ParserHelper::get_optional<uint32_t>(node, "max_bytes").value_or(5);

        return field;
    }

    // ------------------------------------------------------------------------
    // 2. Modular Analyzer Step
    // ------------------------------------------------------------------------
    /**
     * Populates and returns the wire leaf representation for this varint field.
     */
    ResolvedLeafField create_leaf(const FieldAnalyzeContext& ctx) const override {
        ResolvedLeafField leaf;
        init_leaf_base(leaf, ctx);
        return leaf;
    }
};

// Typedef for backward compatibility
using VarintFieldNode = VarintField;

namespace DSLParser {
inline std::shared_ptr<FieldBase> parse_varint_field(const std::string& name, const YAML::Node& node) {
    return VarintField::parse(name, node);
}
} // namespace DSLParser
