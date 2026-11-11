#pragma once

#include "resolved_types.hpp"
#include "../Parser/ast.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace DSLAnalyzer {

// ============================================================================
// Analyzer: Semantic Analysis Engine & Wire Layout Resolver
// ============================================================================
/// Traverses the packet layout, resolves sequential and nested recursive types,
/// and computes (offset, size) metadata for all wire leaves by delegating
/// field analysis modularly to each field's create_leaf() method.
class Analyzer {
public:
    explicit Analyzer(const ProtocolAST& ast) : ast_(ast) {}

    /// Executes full semantic analysis and returns the resolved context
    ResolvedContext analyze() {
        ResolvedContext ctx;
        ctx.protocol_name = ast_.protocol_name;
        ctx.transport = ast_.transport;
        ctx.port = ast_.default_port;

        // Phase 1: Build symbol lookup tables
        index_types();
        index_lp_resolutions();

        // Phase 2: Traverse layout and resolve all leaves
        traverse_layout(ctx);

        // Phase 3: Validate observability filters against resolved leaves
        validate_filters(ctx);

        return ctx;
    }

    /// Static convenience helper
    static ResolvedContext analyze(const ProtocolAST& ast) {
        Analyzer analyzer(ast);
        return analyzer.analyze();
    }

private:
    const ProtocolAST& ast_;
    std::unordered_map<std::string, const TypeDefNode*> type_table_;
    std::unordered_map<std::string, LengthPrefixedResolution> lp_table_;

    // ------------------------------------------------------------------------
    // Phase 1: Symbol Indexing
    // ------------------------------------------------------------------------

    /**
     * Indexes types into a symbol lookup table by name.
     *
     * IMPORTANT: Types are NOT visited or analyzed here.
     * They are strictly indexed as an on-demand schema lookup table for layout traversal.
     */
    void index_types() {
        for (const auto& t : ast_.types) {
            if (type_table_.find(t.name) != type_table_.end()) {
                throw std::runtime_error("Semantic Error: Duplicate type definition '" + t.name + "'");
            }
            type_table_[t.name] = &t;
        }
    }

    /**
     * Indexes length-prefixed dynamic field resolutions for fast lookup.
     */
    void index_lp_resolutions() {
        for (const auto& lp : ast_.LPresolution) {
            lp_table_[lp.field_name] = lp;
        }
    }

    // ------------------------------------------------------------------------
    // Phase 2: Layout Traversal & Recursive Field Resolution
    // ------------------------------------------------------------------------

    /**
     * Traverses the packet layout sequence to resolve on-the-wire leaf fields.
     *
     * Invariants guaranteed:
     *   1. Traversal starts solely at `ast.layout`. Types not reached via layout are never visited.
     *   2. Maintains cumulative static offset and the active list of preceding dynamic leaves.
     *   3. Naming starts with the instance name, ensuring repeated types are uniquely resolved:
     *      `<instance_name>.<type1_or_field1>.<type2_or_field2>...<leaf_name>`
     */
    void traverse_layout(ResolvedContext& ctx) {
        uint32_t current_static_offset = 0;
        std::vector<std::string> current_dynamic_fields;

        for (const auto& layout_node : ast_.layout) {
            ResolvedLayoutInstance inst;
            inst.instance_name = layout_node.instance_name;
            inst.type_ref = layout_node.type_ref;

            // Handle explicit offset override on layout instance (e.g. VXLAN inner header offsets)
            if (layout_node.offset_expr) {
                try {
                    current_static_offset = std::stoul(*layout_node.offset_expr);
                } catch (...) {
                    // Non-numeric offset expressions can be handled by an evaluator if needed
                }
            }

            inst.static_offset_start = current_static_offset;

            // Verify that referenced type exists in the symbol table
            if (type_table_.find(layout_node.type_ref) == type_table_.end()) {
                throw std::runtime_error("Semantic Error: Layout instance '" + layout_node.instance_name +
                                         "' references undefined type '" + layout_node.type_ref + "'");
            }

            // Recursively traverse this layout instance's type definition
            visit_type(layout_node.type_ref,
                       layout_node.instance_name,  // path_prefix begins with instance name
                       layout_node.instance_name,  // type_path_prefix begins with instance name
                       inst,
                       ctx,
                       current_static_offset,
                       current_dynamic_fields);

            ctx.layout.push_back(inst);
        }

        ctx.total_static_size = current_static_offset;
        ctx.is_dynamic = !current_dynamic_fields.empty();
    }

    /**
     * Recursively visits a type definition, resolving its fields in sequential wire order.
     *
     * MODULAR DESIGN:
     *   - No type downcasting (`field->as<...>`) is performed.
     *   - If `field->is_recursive()`: recurses down into the target custom type's fields.
     *   - Otherwise: passes `FieldAnalyzeContext` to `field->create_leaf(ctx)`.
     *     Every field creates and populates its own leaf representation modularly.
     *
     * Leaf Sizing & Offset Tracking:
     *   - Cumulative static offset and dynamic predecessors are updated cleanly.
     *   - Only terminal leaves are stored into `inst.leaves`, `ctx.leaves`, and `ctx.leaf_map`.
     */
    void visit_type(const std::string& type_name,
                    const std::string& path_prefix,
                    const std::string& type_path_prefix,
                    ResolvedLayoutInstance& inst,
                    ResolvedContext& ctx,
                    uint32_t& current_static_offset,
                    std::vector<std::string>& current_dynamic_fields) {

        // Retrieve type definition from symbol table
        auto it = type_table_.find(type_name);
        if (it == type_table_.end()) {
            throw std::runtime_error("Semantic Error: Undefined type '" + type_name +
                                     "' referenced at path '" + path_prefix + "'");
        }
        const TypeDefNode* type_def = it->second;

        // Iterate through fields in declaration order
        for (const auto& field : type_def->fields) {
            std::string full_field_name = path_prefix + "." + field->name;

            // Modular recursive check: does this field embed a nested struct type?
            if (field->is_recursive()) {
                std::string nested_type = field->recursive_type_name();
                std::string next_type_path = type_path_prefix + "." + nested_type;
                visit_type(nested_type,
                           full_field_name,
                           next_type_path,
                           inst,
                           ctx,
                           current_static_offset,
                           current_dynamic_fields);
            } else {
                // Leaf field!
                // Construct the analysis context for this field
                FieldAnalyzeContext actx;
                actx.full_name = full_field_name;

                // Handle explicit field offset override if present
                if (field->offset_expr) {
                    try {
                        current_static_offset = std::stoul(*field->offset_expr);
                    } catch (...) {}
                }

                actx.current_static_offset = current_static_offset;
                actx.dynamic_fields_before = current_dynamic_fields;

                // Bind LP resolution metadata if length-prefixed
                auto lp_it = lp_table_.find(field->name);
                if (lp_it == lp_table_.end()) {
                    lp_it = lp_table_.find(full_field_name);
                }
                if (lp_it != lp_table_.end()) {
                    actx.lp_resolution = &lp_it->second;
                }

                // Modular analyzer call: the field creates and populates its own leaf
                ResolvedLeafField leaf = field->create_leaf(actx);

                // Update running offsets (ONLY dynamic leaves are appended to current_dynamic_fields!)
                if (leaf.is_dynamic) {
                    current_dynamic_fields.push_back(leaf.full_name);
                    inst.is_dynamic = true;
                    ctx.is_dynamic = true;
                } else {
                    current_static_offset += leaf.size;
                }

                ctx.total_max_size += leaf.max_size;

                // Store leaf into results
                inst.leaves.push_back(leaf);
                ctx.leaves.push_back(leaf);
                ctx.leaf_map[leaf.full_name] = leaf;

                // Also index by type-based path if different (e.g. instance.Type1.Type2.leaf)
                std::string leaf_type_path = type_path_prefix + "." + field->name;
                if (leaf_type_path != leaf.full_name && ctx.leaf_map.find(leaf_type_path) == ctx.leaf_map.end()) {
                    ctx.leaf_map[leaf_type_path] = leaf;
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    // Phase 3: Observability Filter Validation
    // ------------------------------------------------------------------------

    /**
     * Validates filter predicates against the resolved packet layout leaves.
     *
     * Supports matching by:
     *   1. Exact hierarchical path: `instance.type1.type2.leaf` or `instance.field1.field2.leaf`
     *   2. Suffix match: if leading instance name was omitted (e.g. `type1.type2.leaf`)
     */
    void validate_filters(ResolvedContext& ctx) {
        for (const auto& filter : ast_.filters) {
            auto it = ctx.leaf_map.find(filter.target_field);
            if (it != ctx.leaf_map.end()) {
                ResolvedFilter rf;
                rf.target_field = filter.target_field;
                rf.op = filter.op;
                rf.value = filter.value;
                rf.matched_leaf = it->second;
                ctx.filters.push_back(rf);
                continue;
            }

            // Suffix matching fallback (e.g. if instance prefix was omitted)
            bool matched = false;
            for (const auto& [leaf_name, leaf_node] : ctx.leaf_map) {
                if (leaf_name.length() > filter.target_field.length() &&
                    leaf_name.substr(leaf_name.length() - filter.target_field.length() - 1) == "." + filter.target_field) {
                    ResolvedFilter rf;
                    rf.target_field = leaf_name;
                    rf.op = filter.op;
                    rf.value = filter.value;
                    rf.matched_leaf = leaf_node;
                    ctx.filters.push_back(rf);
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                throw std::runtime_error("Semantic Error: Filter target '" + filter.target_field +
                                         "' not found in resolved packet layout leaves");
            }
        }
    }
};

// ============================================================================
// Convenience Forwarding Function
// ============================================================================

inline ResolvedContext analyze(const ProtocolAST& ast) {
    return Analyzer::analyze(ast);
}

} // namespace DSLAnalyzer
