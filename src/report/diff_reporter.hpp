// src/report/diff_reporter.hpp
#pragma once
#include "diagnostic.hpp"
#include <vector>
#include <iostream>

namespace switchlint {
void print_diff_report(const std::vector<Violation>& old_violations,
                       const std::vector<Violation>& new_violations,
                       bool use_color = true,
                       std::ostream& os = std::cout);
}
