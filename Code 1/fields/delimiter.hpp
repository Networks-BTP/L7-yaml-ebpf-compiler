#pragma once

#include "field_base.hpp"
#include "../Parser/helpers.hpp"
#include <yaml-cpp/yaml.h>
#include <memory>

// ============================================================================
// DelimiterField: Marker-Terminated Variable-Length String or Sequence
// ============================================================================
class DelimiterField : public FieldBase {
public:
    std::string marker;
    uint32_t max_bytes{128};
    bool trim_whitespace{false};

    std::string type_name() const override { return "delimiter"; }
    bool is_dynamic() const override { return true; }
    uint32_t static_size() const override { return 0; }
    uint32_t max_size() const override { return max_bytes; }

    std::shared_ptr<FieldBase> clone() const override {
        return std::make_shared<DelimiterField>(*this);
    }

    // ------------------------------------------------------------------------
    // 1. Modular Parser Step
    // ------------------------------------------------------------------------
    /**
     * Parses a delimiter field definition from a YAML map node.
     *
     * Supported YAML keys:
     *   - marker: (Required) Delimiter byte/sequence (e.g. "\n", " ", ":", "\r\n")
     *   - max_bytes: (Optional) Hard scan limit in bytes for bounded eBPF loops (default 128)
     *   - trim_whitespace: (Optional) Boolean flag to strip leading/trailing spaces
     *   - data_type: (Optional) Target representation (defaults to STRING)
     *   - offset: (Optional) Explicit byte offset expression
     */
    static std::shared_ptr<DelimiterField> parse(const std::string& field_name,
                                                 const YAML::Node& node) {
        std::string context = "Field '" + field_name + "'";
        auto field = std::make_shared<DelimiterField>();
        field->name = field_name;
        field->offset_expr = DSLParser::ParserHelper::get_optional<std::string>(node, "offset");

        std::string raw_data_type = DSLParser::ParserHelper::get_optional<std::string>(node, "data_type").value_or("");
        field->data_type = DSLParser::ParserHelper::parse_data_type(raw_data_type, DataType::STRING);
        field->marker = DSLParser::ParserHelper::get_required<std::string>(node, "marker", context);
        field->max_bytes = DSLParser::ParserHelper::get_optional<uint32_t>(node, "max_bytes").value_or(128);
        field->trim_whitespace = DSLParser::ParserHelper::get_optional<bool>(node, "trim_whitespace").value_or(false);

        return field;
    }

    // ------------------------------------------------------------------------
    // 2. Modular Analyzer Step
    // ------------------------------------------------------------------------
    /**
     * Populates and returns the wire leaf representation for this delimiter field.
     * Sets delimiter marker directly without requiring any type downcasting.
     */
    ResolvedLeafField create_leaf(const FieldAnalyzeContext& ctx) const override {
        ResolvedLeafField leaf;
        init_leaf_base(leaf, ctx);
        leaf.marker = this->marker;
        return leaf;
    }
};

// Typedef for backward compatibility
using DelimiterFieldNode = DelimiterField;

namespace DSLParser {
inline std::shared_ptr<FieldBase> parse_delimiter_field(const std::string& name, const YAML::Node& node) {
    return DelimiterField::parse(name, node);
}
} // namespace DSLParser
