#pragma once

#include "../fields/fields.hpp"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <cstdint>

// ============================================================================
// Abstract Syntax Tree (AST) Model
// ============================================================================

/// Type definition node describing a packet header or composite struct
struct TypeDefNode {
    std::string name;
    std::optional<uint32_t> static_size;
    std::vector<FieldNode> fields;
};

/// Layout node representing an instantiated header/payload in transmission order
struct LayoutNode {
    std::string instance_name;
    std::string type_ref;
    
    // Optional offset expression (if omitted, starts immediately after preceding instance)
    std::optional<std::string> offset_expr;
};

/// Observability filter condition applied during packet parsing
struct FilterNode {
    std::string target_field;
    FilterOp op;
    std::string value;
};

/// Root AST container holding all parsed protocol declarations
struct ProtocolAST {
    std::string protocol_name;
    std::string transport;
    uint16_t default_port{0};
    
    std::vector<TypeDefNode> types;
    std::vector<LayoutNode> layout;
    std::vector<LengthPrefixedResolution> LPresolution;
    std::vector<FilterNode> filters;
};
