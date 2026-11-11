#pragma once

#include "field_base.hpp"
#include "../Parser/helpers.hpp"
#include <yaml-cpp/yaml.h>
#include <memory>

// ============================================================================
// LengthPrefixedField: Payload Sized Dynamically via Length Field
// ============================================================================
class LengthPrefixedField : public FieldBase {
public:
    uint32_t max_bytes{0};
    std::string length_name;
    uint32_t multiplier{1};
    int32_t addend{0};

    std::string type_name() const override { return "length_prefixed"; }
    bool is_dynamic() const override { return true; }
    uint32_t static_size() const override { return 0; }
    uint32_t max_size() const override { return max_bytes; }

    std::shared_ptr<FieldBase> clone() const override {
        return std::make_shared<LengthPrefixedField>(*this);
    }

    // ------------------------------------------------------------------------
    // 1. Modular Parser Step
    // ------------------------------------------------------------------------
    /**
     * Parses a length-prefixed field definition from a YAML map node.
     *
     * Supported YAML keys:
     *   - length_field: (Optional) Identifier of field supplying byte count
     *   - max_bytes: (Optional) Hard cap on size for verifier bounds checking
     *   - data_type: (Optional) Target representation (defaults to BYTES)
     *   - offset: (Optional) Explicit byte offset expression
     */
    static std::shared_ptr<LengthPrefixedField> parse(const std::string& field_name,
                                                      const YAML::Node& node) {
        auto field = std::make_shared<LengthPrefixedField>();
        field->name = field_name;
        field->offset_expr = DSLParser::ParserHelper::get_optional<std::string>(node, "offset");

        std::string raw_data_type = DSLParser::ParserHelper::get_optional<std::string>(node, "data_type").value_or("");
        field->data_type = DSLParser::ParserHelper::parse_data_type(raw_data_type, DataType::BYTES);
        field->max_bytes = DSLParser::ParserHelper::get_optional<uint32_t>(node, "max_bytes").value_or(0);
        field->length_name = DSLParser::ParserHelper::get_optional<std::string>(node, "length_field").value_or("");

        return field;
    }

    // ------------------------------------------------------------------------
    // 2. Modular Analyzer Step
    // ------------------------------------------------------------------------
    /**
     * Populates and returns the wire leaf representation for this length-prefixed field.
     * Binds resolution metadata (length field reference, multiplier, addend, bounds)
     * without requiring any type downcasting from Analyzer.
     */
    ResolvedLeafField create_leaf(const FieldAnalyzeContext& ctx) const override {
        ResolvedLeafField leaf;
        init_leaf_base(leaf, ctx);

        if (ctx.lp_resolution) {
            leaf.max_size = ctx.lp_resolution->max_bytes;
            leaf.length_name = ctx.lp_resolution->length_name;
            leaf.multiplier = ctx.lp_resolution->multiplier;
            leaf.addend = ctx.lp_resolution->addend;
        } else if (!this->length_name.empty()) {
            leaf.max_size = this->max_bytes;
            leaf.length_name = this->length_name;
            leaf.multiplier = this->multiplier;
            leaf.addend = this->addend;
        }

        return leaf;
    }
};

// Typedef for backward compatibility
using LengthPrefixedFieldNode = LengthPrefixedField;

namespace DSLParser {
inline std::shared_ptr<FieldBase> parse_length_prefixed_field(const std::string& name, const YAML::Node& node) {
    return LengthPrefixedField::parse(name, node);
}
} // namespace DSLParser
