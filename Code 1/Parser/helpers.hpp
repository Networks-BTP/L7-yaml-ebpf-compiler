#pragma once

#include <yaml-cpp/yaml.h>
#include <string>
#include <algorithm>
#include <cctype>
#include <optional>
#include <stdexcept>
#include <type_traits>

namespace DSLParser {

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

std::string to_lower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c){ return std::tolower(c); });
    return str;
}

template <typename T = std::string>
T get_required_field(const YAML::Node& node, const std::string& key, const std::string& context) {
    if (!node[key]) {
        throw std::runtime_error("Parsing Error [" + context + "]: Missing required key '" + key + "'");
    }
    if (node[key].IsNull() || (node[key].IsScalar() && trim(node[key].as<std::string>()).empty())) {
        throw std::runtime_error("Parsing Error [" + context + "]: Key '" + key + "' is present but has no value assigned");
    }
    try {
        return node[key].as<T>();
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("Parsing Error [" + context + "]: Failed to parse value for key '" + key + "' (" + e.what() + ")");
    }
}

template <typename T>
std::optional<T> get_optional_field(const YAML::Node& node, const std::string& key) {
    if (node[key] && !node[key].IsNull()) {
        if constexpr (std::is_same_v<T, std::string>) {
            std::string val = trim(node[key].as<std::string>());
            if (!val.empty()) return val;
        } else {
            return node[key].as<T>();
        }
    }
    return std::nullopt;
}

} // namespace DSLParser