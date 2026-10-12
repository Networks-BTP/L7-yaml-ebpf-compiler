#include "parser.hpp"
#include "analyzer.hpp"
#include "codegen.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <protocol.yaml> [output_dir]\n";
        return 2;
    }

    const std::string input_path = argv[1];
    const std::string out_dir = (argc >= 3) ? argv[2] : ".";

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
        DSLCodeGen::generate(ctx, out_dir);
    } catch (const YAML::Exception& e) {
        std::cerr << "YAML Error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    return 0;
}