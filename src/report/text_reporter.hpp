// src/report/text_reporter.hpp
#pragma once
#include "diagnostic.hpp"
#include <vector>

namespace switchlint {
void print_text_report(const std::vector<Violation>& violations,
                       bool use_color = true);
} // namespace switchlint
