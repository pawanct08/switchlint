// include/diagnostic.hpp
// Violation and severity types for switchlint rule output.
#pragma once

#include <string>

namespace switchlint {

enum class Severity { ERROR, WARN, INFO };

inline std::string to_string(Severity s) {
    switch (s) {
        case Severity::ERROR: return "ERROR";
        case Severity::WARN:  return "WARN";
        case Severity::INFO:  return "INFO";
    }
    return "UNKNOWN";
}

struct Violation {
    Severity    severity{Severity::ERROR};
    std::string rule_id;
    std::string stream_id;  // empty → topology-level violation
    std::string node_id;
    std::string port_id;
    std::string message;
    int         line_number{1};
};

struct Suppression {
    std::string rule_id;
    std::string stream_id;
    std::string reason;
};

} // namespace switchlint
