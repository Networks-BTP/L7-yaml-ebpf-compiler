#pragma once

#include <string>
#include <vector>
#include <memory>
#include <variant>
#include <optional>
#include <cstdint>

// Data Type Enum: Defines standard data representations across all fields
enum class DataType {
    INT,        // Unsigned/signed integers (uint8_t, uint16_t, uint32_t, uint64_t)
    STRING,     // Fixed or dynamic character sequences (null-terminated or bounded char arrays)
    BYTES,      // Opaque raw byte buffers (e.g. MAC, IPv6, SHA hashes, payloads)
    FLOAT,      // Floating point numbers
    BOOLEAN     // 1-bit / 1-byte boolean flags
};

enum class Endianness { LITTLE, BIG, HOST };
enum class FilterOp { EQUAL, NOT_EQUAL, GREATER_THAN, LESS_THAN };

// Base field node properties -> No TLV and Conditional for now
struct FieldBase {
    std::string name;
    
    // Every field node now explicitly declares its target data type
    DataType data_type{DataType::INT};

    // Optional offset expression.
    // If std::nullopt, the field starts immediately after the preceding field.
    std::optional<std::string> offset_expr;
};

// 1. Fixed / Bitfield Node
struct FixedFieldNode : public FieldBase {
    uint32_t size_bytes{4}; // e.g., 1, 2, 4, 8
    // Endianness endian{Endianness::BIG};
    // std::optional<uint8_t> bit_offset;
    // std::optional<uint8_t> bit_size;
};

// 2. Updated Length-Prefixed Node
struct LengthPrefixedFieldNode : public FieldBase {};

// 3. Delimiter Node
struct DelimiterFieldNode : public FieldBase {
    std::string marker;         // e.g., " ", "\r\n", ":"
    uint32_t max_bytes{128};    // Bounded scan limit
    bool trim_whitespace{false}; // Strips leading/trailing 0x20 and \t if true
};

// 4. Varint Node
struct VarintFieldNode : public FieldBase {
    uint32_t max_bytes{5};      // Maximum LEB128 bytes (5 for 32-bit uint)
};

// Variant type containing all concrete field nodes
using FieldNode = std::variant<
    FixedFieldNode,
    LengthPrefixedFieldNode,
    DelimiterFieldNode,
    VarintFieldNode
>;

// Type Definition Struct
struct TypeDefNode {
    std::string name;
    std::optional<uint32_t> static_size;
    std::vector<FieldNode> fields;
};

// Layout Instantiation Node
struct LayoutNode {
    std::string instance_name;
    std::string type_ref;
    
    // Rule 2: Optional layout offset expression.
    // If std::nullopt, starts immediately after preceding layout instance in packet stream.
    std::optional<std::string> offset_expr;
    
    // std::optional<std::string> condition;
};

struct LengthPrefixedResolution{
    std::string field_name;
    std::string length_name;
    uint32_t multiplier{1};                      // e.g., IHL * 4
    int32_t addend{0};                           // e.g., Length - 2
    uint32_t max_bytes;                          // Hard cap for eBPF verifier
};

// Observability Filter Node
struct FilterNode {
    std::string target_field;
    FilterOp op;
    std::string value;
};

// Root AST Node
struct ProtocolAST {
    std::string protocol_name;
    std::string transport;
    uint16_t default_port{0};
    
    std::vector<TypeDefNode> types;
    std::vector<LayoutNode> layout;
    std::vector<LengthPrefixedResolution> LPresolution;
    std::vector<FilterNode> filters;
};