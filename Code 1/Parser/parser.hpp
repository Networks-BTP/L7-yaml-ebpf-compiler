#pragma once

#include "ast.hpp"
#include "section_parsers.hpp"
#include <yaml-cpp/yaml.h>
#include <string>

namespace DSLParser {

inline ProtocolAST parse_yaml(const std::string& yaml_content) {
    YAML::Node root = YAML::Load(yaml_content);
    ProtocolAST ast;

    parse_root_metadata(root, ast);
    parse_types_section(root, ast);
    parse_layout_section(root, ast);
    parse_lp_resolutions_section(root, ast);
    parse_filters_section(root, ast);

    return ast;
}

} // namespace DSLParser