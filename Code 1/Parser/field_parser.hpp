#pragma once

#include "../fields/fields.hpp"
#include <string>
#include <memory>
#include <yaml-cpp/yaml.h>

namespace DSLParser {

// ============================================================================
// FieldParser: Dispatches Field Parsing to FieldRegistry
// ============================================================================
class FieldParser {
public:
    /// Parses a field node by dispatching to the central FieldRegistry.
    /// This keeps field types completely modular.
    static FieldNode parse(const std::string& field_name, const YAML::Node& node) {
        return FieldRegistry::instance().parse(field_name, node);
    }
};

// Compatibility wrapper
inline FieldNode parse_field(const std::string& field_name, const YAML::Node& node) {
    return FieldParser::parse(field_name, node);
}

} // namespace DSLParser
