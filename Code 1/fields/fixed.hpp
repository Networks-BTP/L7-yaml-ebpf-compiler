#pragma once

#include "field_base.hpp"
#include "../Parser/helpers.hpp"
#include <yaml-cpp/yaml.h>
#include <memory>

// ============================================================================
// FixedField: Fixed-Width Integral or Raw Byte Sequence
// ============================================================================
class FixedField : public FieldBase {
public:
    uint32_t size_bytes{4};

    std::string type_name() const override { return "fixed"; }
    bool is_dynamic() const override { return false; }
    uint32_t static_size() const override { return size_bytes; }
    uint32_t max_size() const override { return size_bytes; }

    std::shared_ptr<FieldBase> clone() const override {
        return std::make_shared<FixedField>(*this);
    }

    // ------------------------------------------------------------------------
    // 1. Modular Parser Step
    // ------------------------------------------------------------------------
    /**
     * Parses a fixed-size field definition from a YAML map node.
     * 
     * Supported YAML keys:
     *   - size: Integer byte width (default 4 if omitted, or overridden by default_size)
     *   - data_type: Target data representation (e.g. int, bytes; defaults to INT)
     *   - offset: Optional explicit byte offset expression
     */
    static std::shared_ptr<FixedField> parse(const std::string& field_name,
                                             const YAML::Node& node,
                                             uint32_t default_size = 4) {
        auto field = std::make_shared<FixedField>();
        field->name = field_name;
        field->offset_expr = DSLParser::ParserHelper::get_optional<std::string>(node, "offset");

        std::string raw_data_type = DSLParser::ParserHelper::get_optional<std::string>(node, "data_type").value_or("");
        field->data_type = DSLParser::ParserHelper::parse_data_type(raw_data_type, DataType::INT);
        field->size_bytes = DSLParser::ParserHelper::get_optional<uint32_t>(node, "size").value_or(default_size);

        return field;
    }

    // ------------------------------------------------------------------------
    // 2. Modular Analyzer Step
    // ------------------------------------------------------------------------
    /**
     * Populates and returns the wire leaf representation for this fixed field.
     */
    ResolvedLeafField create_leaf(const FieldAnalyzeContext& ctx) const override {
        ResolvedLeafField leaf;
        init_leaf_base(leaf, ctx);
        return leaf;
    }
};

// Typedef for backward compatibility
using FixedFieldNode = FixedField;

namespace DSLParser {
inline std::shared_ptr<FieldBase> parse_fixed_field(const std::string& name, const YAML::Node& node, uint32_t size = 4) {
    return FixedField::parse(name, node, size);
}
} // namespace DSLParser
