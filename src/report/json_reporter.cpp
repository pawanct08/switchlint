// src/report/json_reporter.cpp
// Structured JSON output — suitable for CI tools and dashboards.
// Uses nlohmann/json (header-only, bundled via CMake FetchContent).
#include "json_reporter.hpp"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>

namespace switchlint {

using json = nlohmann::json;

static std::string severity_str(Severity s) {
    switch (s) {
        case Severity::ERROR: return "error";
        case Severity::WARN:  return "warning";
        case Severity::INFO:  return "info";
    }
    return "unknown";
}

static json violation_to_json(const Violation& v) {
    json j;
    j["severity"]  = severity_str(v.severity);
    j["rule_id"]   = v.rule_id;
    j["message"]   = v.message;
    if (!v.stream_id.empty()) j["stream_id"] = v.stream_id;
    if (!v.node_id.empty())   j["node_id"]   = v.node_id;
    if (!v.port_id.empty())   j["port_id"]   = v.port_id;
    return j;
}

void print_json_report(const std::vector<Violation>& violations,
                       std::ostream& out)
{
    int errors = 0, warnings = 0;
    for (const auto& v : violations) {
        if (v.severity == Severity::ERROR) ++errors;
        else if (v.severity == Severity::WARN) ++warnings;
    }

    json report;
    report["summary"]["errors"]   = errors;
    report["summary"]["warnings"] = warnings;
    report["violations"] = json::array();

    for (const auto& v : violations)
        report["violations"].push_back(violation_to_json(v));

    out << report.dump(2) << '\n';
}

void write_json_report(const std::vector<Violation>& violations,
                       const std::string& path)
{
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot open output file: " + path);
    print_json_report(violations, f);
}

} // namespace switchlint
