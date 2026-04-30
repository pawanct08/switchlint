// src/report/text_reporter.cpp
// Human-readable terminal output with ANSI colour codes.
#include "text_reporter.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>

namespace switchlint {

// ANSI colour codes — disabled on Windows unless ENABLE_VIRTUAL_TERMINAL_PROCESSING set
static const char* RESET  = "\033[0m";
static const char* RED    = "\033[31m";
static const char* YELLOW = "\033[33m";
static const char* CYAN   = "\033[36m";
static const char* BOLD   = "\033[1m";

void print_text_report(const std::vector<Violation>& violations,
                       bool use_color,
                       std::ostream& os)
{
    int errors = 0, warnings = 0, infos = 0;

    for (const auto& v : violations) {
        std::string prefix, color;
        switch (v.severity) {
            case Severity::ERROR: prefix = "[ERROR]"; color = RED;    ++errors;   break;
            case Severity::WARN:  prefix = "[WARN] "; color = YELLOW; ++warnings; break;
            case Severity::INFO:  prefix = "[INFO] "; color = CYAN;   ++infos;    break;
        }

        if (use_color) os << BOLD << color;
        os << prefix;
        if (use_color) os << RESET;
        os << " " << v.message << '\n';
    }

    // Summary line
    os << '\n';
    if (use_color) os << BOLD;
    os << "Summary: " << errors << " error(s), "
       << warnings << " warning(s), "
       << infos << " info(s)";
    if (use_color) os << RESET;
    os << '\n';
}

} // namespace switchlint
