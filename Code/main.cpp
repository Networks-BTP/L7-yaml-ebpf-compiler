#include "parser.hpp"
#include "analyzer.hpp"
#include "codegen.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

int main(int argc, char** argv) {
    bool telemetry = false;
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--telemetry") telemetry = true;
        else positional.push_back(a);
    }
    if (positional.empty() || positional.size() > 2) {
        std::cerr << "Usage: " << argv[0] << " [--telemetry] <protocol.yaml> [output_dir]\n"
                  << "  --telemetry  also generate event/counter reporting, loader.c and a Makefile\n";
        return 2;
    }

    const std::string input_path = positional[0];
    const std::string out_dir = (positional.size() >= 2) ? positional[1] : ".";

    std::ifstream in(input_path);
    if (!in) {
        std::cerr << "Error: cannot open '" << input_path << "'\n";
        return 1;
    }
    std::stringstream buffer;
    buffer << in.rdbuf();

    try {
        std::filesystem::create_directories(out_dir);

        // 1. YAML -> AST
        ProtocolAST ast = DSLParser::parse_yaml(buffer.str());
        std::cout << "[Parser]   protocol '" << ast.protocol_name << "': "
                  << ast.types.size() << " type(s), "
                  << ast.layout.size() << " layout instance(s), "
                  << ast.filters.size() << " filter(s)\n";

        // 2. AST -> resolved symbol table (+ semantic checks)
        DSLAnalyzer::ResolvedContext ctx = DSLAnalyzer::analyze(ast);
        for (const auto& name : ctx.type_order) {
            const auto& t = ctx.types.at(name);
            std::cout << "[Analyzer] type '" << name << "': "
                      << (t.is_dynamic ? "dynamic" : "static")
                      << ", min=" << t.static_min_size
                      << " max=" << t.static_max_size << " bytes\n";
        }

        // 3. Resolved context -> C files
        DSLCodeGen::generate(ctx, out_dir, telemetry);
    } catch (const YAML::Exception& e) {
        std::cerr << "YAML Error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}