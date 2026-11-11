#include "Parser/parser.hpp"
#include "Analyzer/analyzer.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <protocol.yaml>\n";
        return 1;
    }

    const std::string input_path = argv[1];
    std::ifstream in(input_path);
    if (!in) {
        std::cerr << "Error: cannot open '" << input_path << "'\n";
        return 1;
    }

    std::stringstream buffer;
    buffer << in.rdbuf();

    try {
        std::cout << "========================================================\n";
        std::cout << " 1. PARSING YAML SPECIFICATION\n";
        std::cout << "========================================================\n";
        ProtocolAST ast = DSLParser::parse_yaml(buffer.str());
        std::cout << "[Parser] Protocol: " << ast.protocol_name << "\n";
        std::cout << "[Parser] Transport: " << ast.transport << ", Default Port: " << ast.default_port << "\n";
        std::cout << "[Parser] Defined Types: " << ast.types.size() << "\n";
        std::cout << "[Parser] Layout Instances: " << ast.layout.size() << "\n";
        std::cout << "[Parser] LP Resolutions: " << ast.LPresolution.size() << "\n";
        std::cout << "[Parser] Filters: " << ast.filters.size() << "\n\n";

        std::cout << "========================================================\n";
        std::cout << " 2. ANALYZING LAYOUT & RECURSIVE FIELDS\n";
        std::cout << "========================================================\n";
        DSLAnalyzer::ResolvedContext ctx = DSLAnalyzer::analyze(ast);

        std::cout << "[Analyzer] Protocol: " << ctx.protocol_name << "\n";
        std::cout << "[Analyzer] Total Static Size: " << ctx.total_static_size << " bytes\n";
        std::cout << "[Analyzer] Overall Dynamic: " << (ctx.is_dynamic ? "YES" : "NO") << "\n";
        std::cout << "[Analyzer] Total Max Size: " << ctx.total_max_size << " bytes\n\n";

        std::cout << "--- Layout Instances ---\n";
        for (const auto& inst : ctx.layout) {
            std::cout << "  Instance: '" << inst.instance_name << "' [Type: " << inst.type_ref
                      << ", Start Offset: " << inst.static_offset_start
                      << ", Dynamic: " << (inst.is_dynamic ? "YES" : "NO")
                      << ", Leaves: " << inst.leaves.size() << "]\n";
        }

        std::cout << "\n--- Resolved Leaf Fields ((offset, size) pairs) ---\n";
        std::cout << std::left 
                  << std::setw(36) << "Field Path"
                  << std::setw(15) << "Type"
                  << std::setw(15) << "Static Offset"
                  << std::setw(12) << "Size"
                  << std::setw(12) << "Is Dynamic"
                  << "Dynamic Predecessors"
                  << "\n";
        std::cout << std::string(115, '-') << "\n";

        for (const auto& leaf : ctx.leaves) {
            std::string size_str = leaf.is_dynamic 
                                   ? ("max " + std::to_string(leaf.max_size)) 
                                   : std::to_string(leaf.size);

            std::string dyn_str = "";
            if (!leaf.dynamic_fields_before.empty()) {
                dyn_str = "[";
                for (size_t i = 0; i < leaf.dynamic_fields_before.size(); ++i) {
                    if (i > 0) dyn_str += ", ";
                    dyn_str += leaf.dynamic_fields_before[i];
                }
                dyn_str += "]";
            } else {
                dyn_str = "None";
            }

            std::cout << std::left 
                      << std::setw(36) << leaf.full_name
                      << std::setw(15) << leaf.field_type
                      << std::setw(15) << leaf.static_offset
                      << std::setw(12) << size_str
                      << std::setw(12) << (leaf.is_dynamic ? "true" : "false")
                      << dyn_str
                      << "\n";
        }

        std::cout << "\n--- Validated Observability Filters ---\n";
        for (const auto& f : ctx.filters) {
            std::cout << "  Filter on '" << f.target_field << "' -> Value: '" << f.value << "' (Valid leaf matched)\n";
        }
        std::cout << "\n[Analyzer] Analysis completed successfully.\n";

    } catch (const std::exception& e) {
        std::cerr << "\n[Error] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
