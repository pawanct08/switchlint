// src/report/json_reporter.hpp
#pragma once
#include "diagnostic.hpp"
#include <iosfwd>
#include <string>
#include <vector>

namespace switchlint {
void print_json_report(const std::vector<Violation>& violations,
                       std::ostream& out);
void write_json_report(const std::vector<Violation>& violations,
                       const std::string& path);
} // namespace switchlint
