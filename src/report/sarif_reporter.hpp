// src/report/sarif_reporter.hpp
#pragma once
#include "diagnostic.hpp"
#include <vector>
#include <iostream>

namespace switchlint {
void print_sarif_report(const std::vector<Violation>& violations, std::ostream& os = std::cout);
}
