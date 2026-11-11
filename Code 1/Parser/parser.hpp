#pragma once

#include "ast.hpp"
#include "section_parser.hpp"
#include <yaml-cpp/yaml.h>
#include <string>

namespace DSLParser {

// ============================================================================
// Parser: Main YAML-to-AST Compiler Frontend
// ============================================================================
class Parser {
public:
    /**
     * Parses a raw YAML specification string into a structured ProtocolAST.
     *
     * Coordinates the multi-stage frontend parsing pipeline:
     *   1. Root metadata: Extracts protocol name, transport protocol, and default port.
     *   2. Types: Parses struct schemas and registers fixed/dynamic field definitions.
     *   3. Layout: Parses transmission order of packet header/payload instances.
     *   4. LP Resolutions: Parses length-to-field dynamic bindings.
     *   5. Filters: Parses observability filter predicates.
     */
    static ProtocolAST parse_yaml(const std::string& yaml_content) {
        YAML::Node root = YAML::Load(yaml_content);
        ProtocolAST ast;

        SectionParser::parse_root_metadata(root, ast);
        SectionParser::parse_types_section(root, ast);
        SectionParser::parse_layout_section(root, ast);
        SectionParser::parse_lp_resolutions_section(root, ast);
        SectionParser::parse_filters_section(root, ast);

        return ast;
    }
};

// Convenience top-level wrapper
inline ProtocolAST parse_yaml(const std::string& yaml_content) {
    return Parser::parse_yaml(yaml_content);
}

} // namespace DSLParser
