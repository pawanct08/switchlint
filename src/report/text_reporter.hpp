// src/report/text_reporter.hpp
#pragma once
#include "diagnostic.hpp"
#include <vector>
#include <iostream>

namespace switchlint {
void print_text_report(const std::vector<Violation>& violations,
                       bool use_color = true,
                       std::ostream& os = std::cout);
} // namespace switchlint
