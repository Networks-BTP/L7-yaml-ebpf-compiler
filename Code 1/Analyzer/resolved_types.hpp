#pragma once

#include "../fields/fields.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <sstream>

namespace DSLAnalyzer {

// Use the ResolvedLeafField defined in field_base.hpp so all field classes can access it directly
using ResolvedLeafField = ::ResolvedLeafField;

// ============================================================================
// ResolvedLayoutInstance: Instantiated Header/Payload in Layout
// ============================================================================
/// Represents an entry in the protocol layout sequence with all its resolved leaves.
struct ResolvedLayoutInstance {
    std::string instance_name;              /// Layout instance identifier (e.g. "hdr", "body")
    std::string type_ref;                   /// Underlying struct type reference
    uint32_t static_offset_start{0};        /// Static byte offset where this instance starts
    bool is_dynamic{false};                 /// True if any leaf within this instance is dynamic
    std::vector<ResolvedLeafField> leaves;  /// Ordered leaf fields belonging to this instance
};

// ============================================================================
// ResolvedFilter: Validated Observability Predicate
// ============================================================================
/// Predicate validated against the resolved packet layout leaves.
struct ResolvedFilter {
    std::string target_field;                       /// Full path or alias matched (e.g. "hdr.type1.Inner.val")
    FilterOp op;                                    /// Comparison operator
    std::string value;                              /// Comparison value literal
    std::optional<ResolvedLeafField> matched_leaf;  /// Metadata of the matched leaf field
};

// ============================================================================
// ResolvedContext: Complete Semantic Analysis Result
// ============================================================================
/// Symbol table and layout resolution context produced by the Analyzer.
struct ResolvedContext {
    std::string protocol_name;
    std::string transport;
    uint16_t port{0};

    // Sequential layout instances in packet order
    std::vector<ResolvedLayoutInstance> layout;

    // Flat ordered list of all leaf fields in transmission order
    std::vector<ResolvedLeafField> leaves;

    // Map for O(1) lookup of leaves by hierarchical path
    std::unordered_map<std::string, ResolvedLeafField> leaf_map;

    // Validated observability filters
    std::vector<ResolvedFilter> filters;

    // Summary metrics
    uint32_t total_static_size{0};
    uint32_t total_max_size{0};
    bool is_dynamic{false};
};

} // namespace DSLAnalyzer
