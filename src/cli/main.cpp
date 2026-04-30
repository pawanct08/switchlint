// src/cli/main.cpp
// switchlint — Automotive Ethernet Switch Config Validator
// Usage: switchlint [options] <topology.yaml>
//
// Options:
//   --format text|json      Output format (default: text)
//   --output <file>         Write output to file instead of stdout
//   --rules RULE1,RULE2     Run only the specified rules
//   --list-rules            Print all available rules and exit
//   --no-color              Disable ANSI color codes
//   --fail-on-warn          Exit 1 on warnings too (default: only on errors)
//   --help                  Show this help message

#include "rule_engine.hpp"
#include "topology.hpp"
#include "../parser/yaml_parser.hpp"
#include "../report/text_reporter.hpp"
#include "../report/json_reporter.hpp"
#include "../report/diff_reporter.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>

#ifdef _WIN32
#  include <windows.h>   // EnableVirtualTerminalProcessing for ANSI colors
#  undef ERROR
#endif

static void enable_ansi_windows() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}

static void print_usage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " [options] <topology.yaml>\n\n"
        "Options:\n"
        "  --format text|json      Output format  (default: text)\n"
        "  --output <file>         Write output to file\n"
        "  --rules RULE1,RULE2     Run only specific rules\n"
        "  --list-rules            List all rules and exit\n"
        "  --no-color              Disable ANSI colors\n"
        "  --fail-on-warn          Exit 1 on warnings too\n"
        "  --strict-unicast-fw     Enforce firewall rules on unicast streams\n"
        "  --diff                  Compare violations between two topologies\n"
        "  --help                  Show this message\n";
}

int main(int argc, char* argv[]) {
    enable_ansi_windows();

    // ─── argument parsing ──────────────────────────────────────────────────
    std::string format      = "text";
    std::string output_file;
    std::string rules_filter;
    std::vector<std::string> input_files;
    bool use_color      = true;
    bool fail_on_warn   = false;
    bool list_rules_opt = false;
    bool strict_unicast_fw = false;
    bool diff_mode      = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--list-rules") {
            list_rules_opt = true;
        } else if (arg == "--no-color") {
            use_color = false;
        } else if (arg == "--fail-on-warn") {
            fail_on_warn = true;
        } else if (arg == "--strict-unicast-fw") {
            strict_unicast_fw = true;
        } else if (arg == "--format" && i + 1 < argc) {
            format = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_filter = argv[++i];
        } else if (arg == "--diff") {
            diff_mode = true;
        } else if (arg[0] != '-') {
            input_files.push_back(arg);
        } else {
            std::cerr << "Unknown option: " << arg << '\n';
            print_usage(argv[0]);
            return 2;
        }
    }

    // ─── build rule registry ───────────────────────────────────────────────
    switchlint::RuleRegistry registry;
    switchlint::register_builtin_rules(registry, strict_unicast_fw);

    if (list_rules_opt) {
        for (const auto& [id, desc] : registry.list_rules())
            std::cout << id << "  " << desc << '\n';
        return 0;
    }

    if (input_files.empty()) {
        std::cerr << "Error: no input file specified.\n";
        print_usage(argv[0]);
        return 2;
    }

    if (diff_mode && input_files.size() < 2) {
        std::cerr << "Error: --diff mode requires two input files.\n";
        return 2;
    }

    auto run_validation = [&](const std::string& path) {
        switchlint::Topology topo = switchlint::parse_yaml(path);
        std::vector<switchlint::Violation> v;
        if (rules_filter.empty()) {
            v = registry.run_all(topo);
        } else {
            std::istringstream ss(rules_filter);
            std::string token;
            while (std::getline(ss, token, ',')) {
                auto res = registry.run(token, topo);
                v.insert(v.end(), res.begin(), res.end());
            }
        }
        return v;
    };

    if (diff_mode) {
        std::vector<switchlint::Violation> v1 = run_validation(input_files[0]);
        std::vector<switchlint::Violation> v2 = run_validation(input_files[1]);
        
        int new_violations = 0;
        if (output_file.empty()) {
            new_violations = switchlint::print_diff_report(v1, v2, use_color, std::cout);
        } else {
            std::ofstream ofs(output_file);
            if (!ofs) {
                std::cerr << "[FATAL] Failed to open output file: " << output_file << '\n';
                return 2;
            }
            new_violations = switchlint::print_diff_report(v1, v2, false, ofs);
        }
        return (new_violations > 0) ? 1 : 0;
    }

    std::vector<switchlint::Violation> violations;
    try {
        violations = run_validation(input_files[0]);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << '\n';
        return 2;
    }

    // ─── apply suppressions ────────────────────────────────────────────────
    auto suppressions = switchlint::parse_suppressions(".switchlintignore");
    if (!suppressions.empty()) {
        violations.erase(std::remove_if(violations.begin(), violations.end(),
            [&](const switchlint::Violation& v) {
                for (const auto& s : suppressions) {
                    bool rule_match   = s.rule_id.empty()   || s.rule_id == v.rule_id;
                    bool stream_match = s.stream_id.empty() || s.stream_id == v.stream_id;
                    if (rule_match && stream_match) return true;
                }
                return false;
            }), violations.end());
    }

    // ─── report ────────────────────────────────────────────────────────────
    if (format == "json") {
        if (output_file.empty())
            switchlint::print_json_report(violations, std::cout);
        else
            switchlint::write_json_report(violations, output_file);
    } else {
        if (output_file.empty()) {
            switchlint::print_text_report(violations, use_color, std::cout);
        } else {
            std::ofstream ofs(output_file);
            if (!ofs) {
                std::cerr << "[FATAL] Failed to open output file: " << output_file << '\n';
                return 2;
            }
            // disable color when writing to file
            switchlint::print_text_report(violations, false, ofs);
        }
    }

    // ─── exit code ─────────────────────────────────────────────────────────
    bool has_errors = std::any_of(violations.begin(), violations.end(),
        [](const switchlint::Violation& v) {
            return v.severity == switchlint::Severity::ERROR;
        });
    bool has_warns = std::any_of(violations.begin(), violations.end(),
        [](const switchlint::Violation& v) {
            return v.severity == switchlint::Severity::WARN;
        });

    if (has_errors) return 1;
    if (fail_on_warn && has_warns) return 1;
    return 0;
}
