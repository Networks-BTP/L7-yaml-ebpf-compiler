#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <cstdint>
#include <sstream>

// ============================================================================
// Data Representation Types & Enums
// ============================================================================

/// Represents primitive and user-defined data representations across all fields
struct DataType {
    enum Primitive {
        INT,        // Unsigned/signed integers (uint8_t, uint16_t, uint32_t, uint64_t)
        STRING,     // Fixed or dynamic character sequences
        BYTES,      // Raw byte buffers / payloads
        FLOAT,      // Floating point numbers
        BOOLEAN,    // 1-bit / 1-byte boolean flags
        CUSTOM      // User-defined / recursive struct type
    };

    Primitive primitive{Primitive::INT};
    std::string custom_type_name; // Populated when primitive == Primitive::CUSTOM

    bool is_primitive() const { return primitive != Primitive::CUSTOM; }
    bool is_custom() const { return primitive == Primitive::CUSTOM; }
};

enum class Endianness { LITTLE, BIG, HOST };
enum class FilterOp { EQUAL, NOT_EQUAL, GREATER_THAN, LESS_THAN };

/// Length-prefixed resolution rule binding a length field to a dynamic payload
struct LengthPrefixedResolution {
    std::string field_name;
    std::string length_name;
    uint32_t multiplier{1};                      // e.g. IHL * 4
    int32_t addend{0};                           // e.g. Length - 2
    uint32_t max_bytes{0};                       // Verifier bounds limit
};

// ============================================================================
// ResolvedLeafField: Terminal Leaf Element in the Packet Wire Layout
// ============================================================================
/// For each wire leaf, we maintain:
///   1. `static_offset`: sum of static sizes of all fields preceding this leaf
///   2. `dynamic_fields_before`: list of previous dynamic leaves only
///   3. `is_dynamic`: boolean indicating whether this leaf itself is dynamic
/// Together with size and max_size, forming the exact (offset, size) pair.
struct ResolvedLeafField {
    std::string full_name;                          /// Fully qualified hierarchical path (e.g. "hdr.type1.Inner.magic")
    std::string short_name;                         /// Terminal field identifier (e.g. "magic")
    std::string field_type;                         /// Field type name (e.g. "fixed", "delimiter", "varint")
    DataType data_type;                             /// Target data representation

    // --- The 3 required leaf properties ---
    uint32_t static_offset{0};                      /// Cumulative sum of fixed/static offsets preceding this leaf
    std::vector<std::string> dynamic_fields_before; /// Ordered list of preceding dynamic leaves only
    bool is_dynamic{false};                         /// True if this leaf itself has variable size

    // --- Sizing properties to form the (offset, size) pair ---
    uint32_t size{0};                               /// Fixed byte size (if not dynamic), 0 if variable
    uint32_t max_size{0};                           /// Maximum upper bound in bytes (for verifier bounds checks)

    // Optional attributes
    std::optional<std::string> offset_expr;         /// Explicit offset expression from YAML
    std::string marker;                             /// Delimiter byte/sequence (if delimiter field)
    std::string length_name;                        /// Dynamic length field identifier (if length-prefixed)
    uint32_t multiplier{1};                         /// Multiplier for LP resolution (e.g. IHL * 4)
    int32_t addend{0};                              /// Addend for LP resolution (e.g. len - 2)

    /// Returns true if this field starts at a purely deterministic static offset
    bool is_purely_static_offset() const {
        return dynamic_fields_before.empty();
    }

    /// Formats a readable summary of the (offset, size) pair and dynamism
    std::string to_string() const {
        std::ostringstream oss;
        oss << full_name << " [type=" << field_type
            << ", offset=" << static_offset;
        if (!dynamic_fields_before.empty()) {
            oss << " + dynamic(";
            for (size_t i = 0; i < dynamic_fields_before.size(); ++i) {
                if (i > 0) oss << ", ";
                oss << dynamic_fields_before[i];
            }
            oss << ")";
        }
        oss << ", size=";
        if (is_dynamic) {
            oss << "dynamic(max " << max_size << ")";
        } else {
            oss << size;
        }
        oss << ", is_dynamic=" << (is_dynamic ? "true" : "false") << "]";
        return oss.str();
    }
};

// ============================================================================
// FieldAnalyzeContext: Context Provided by Analyzer to Each Field
// ============================================================================
struct FieldAnalyzeContext {
    std::string full_name;
    uint32_t current_static_offset{0};
    std::vector<std::string> dynamic_fields_before;
    const LengthPrefixedResolution* lp_resolution{nullptr};
};

// ============================================================================
// Abstract Base Class: FieldBase
// ============================================================================
/// Base interface for all field nodes.
/// Provides modular polymorphic hooks for both:
///   1. Frontend parsing (via each subclass's static parse method)
///   2. Semantic analysis (via create_leaf() and is_recursive())
class FieldBase {
public:
    std::string name;
    DataType data_type;
    std::optional<std::string> offset_expr;

    virtual ~FieldBase() = default;

    /// Unique identifier for this field kind (e.g. "fixed", "delimiter", "varint")
    virtual std::string type_name() const = 0;

    /// Returns true if the field's wire size is dynamic/variable at runtime
    virtual bool is_dynamic() const = 0;

    /// Minimum guaranteed static size in bytes (0 for dynamic fields)
    virtual uint32_t static_size() const { return 0; }

    /// Maximum possible size in bytes (used for eBPF verifier bounds checking)
    virtual uint32_t max_size() const { return static_size(); }

    /// Returns true if this field embeds a nested/recursive custom struct type
    virtual bool is_recursive() const { return data_type.is_custom(); }

    /// Returns the target custom type name if this field is recursive
    virtual std::string recursive_type_name() const { return data_type.custom_type_name; }

    /// Backward compatibility aliases
    bool is_custom_type() const { return is_recursive(); }
    std::string custom_type_name() const { return recursive_type_name(); }

    /// Deep copy clone
    virtual std::shared_ptr<FieldBase> clone() const = 0;

    /// Modular analyzer hook: field creates and populates its own ResolvedLeafField
    virtual ResolvedLeafField create_leaf(const FieldAnalyzeContext& ctx) const = 0;

    /// Convenient downcast helper
    template <typename T>
    const T* as() const {
        return dynamic_cast<const T*>(this);
    }

    template <typename T>
    T* as() {
        return dynamic_cast<T*>(this);
    }

protected:
    /// Helper to initialize common leaf properties for any concrete field
    void init_leaf_base(ResolvedLeafField& leaf, const FieldAnalyzeContext& ctx) const {
        leaf.full_name = ctx.full_name;
        leaf.short_name = this->name;
        leaf.field_type = this->type_name();
        leaf.data_type = this->data_type;
        leaf.offset_expr = this->offset_expr;

        // Maintain the 3 required leaf properties:
        leaf.static_offset = ctx.current_static_offset;
        leaf.dynamic_fields_before = ctx.dynamic_fields_before;
        leaf.is_dynamic = this->is_dynamic();
        leaf.size = this->static_size();
        leaf.max_size = this->max_size();
    }
};

using FieldNode = std::shared_ptr<FieldBase>;

inline const FieldBase& get_field_base(const FieldNode& node) {
    return *node;
}

inline FieldBase& get_field_base(FieldNode& node) {
    return *node;
}
