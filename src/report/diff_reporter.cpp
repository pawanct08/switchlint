// src/report/diff_reporter.cpp
#include "diff_reporter.hpp"
#include <set>
#include <map>
#include <tuple>

namespace switchlint {

static const char* RESET  = "\033[0m";
static const char* RED    = "\033[31m";
static const char* GREEN  = "\033[32m";
static const char* YELLOW = "\033[33m";
static const char* BOLD   = "\033[1m";

struct ViolationKey {
    std::string rule_id;
    std::string stream_id;
    std::string node_id;
    std::string port_id;

    bool operator<(const ViolationKey& other) const {
        return std::tie(rule_id, stream_id, node_id, port_id) <
               std::tie(other.rule_id, other.stream_id, other.node_id, other.port_id);
    }
};

static ViolationKey make_key(const Violation& v) {
    return {v.rule_id, v.stream_id, v.node_id, v.port_id};
}

void print_diff_report(const std::vector<Violation>& old_violations,
                       const std::vector<Violation>& new_violations,
                       bool use_color,
                       std::ostream& os)
{
    std::map<ViolationKey, const Violation*> old_map;
    for (const auto& v : old_violations) old_map[make_key(v)] = &v;

    std::map<ViolationKey, const Violation*> new_map;
    for (const auto& v : new_violations) new_map[make_key(v)] = &v;

    std::set<ViolationKey> all_keys;
    for (const auto& kv : old_map) all_keys.insert(kv.first);
    for (const auto& kv : new_map) all_keys.insert(kv.first);

    int new_count = 0, fixed_count = 0, unchanged_count = 0;

    for (const auto& key : all_keys) {
        bool in_old = old_map.count(key);
        bool in_new = new_map.count(key);

        if (in_old && in_new) {
            if (use_color) os << YELLOW << "[UNCHANGED] " << RESET;
            else os << "[UNCHANGED] ";
            os << new_map[key]->message << "\n";
            unchanged_count++;
        } else if (in_new) {
            if (use_color) os << BOLD << RED << "[NEW]       " << RESET;
            else os << "[NEW]       ";
            os << new_map[key]->message << "\n";
            new_count++;
        } else {
            if (use_color) os << GREEN << "[FIXED]     " << RESET;
            else os << "[FIXED]     ";
            os << old_map[key]->message << "\n";
            fixed_count++;
        }
    }

    os << "\nDiff Summary:\n";
    if (use_color) os << BOLD << RED << "  " << new_count << " new" << RESET << "\n";
    else os << "  " << new_count << " new\n";
    
    if (use_color) os << GREEN << "  " << fixed_count << " fixed" << RESET << "\n";
    else os << "  " << fixed_count << " fixed\n";
    
    os << "  " << unchanged_count << " unchanged\n";
}

}
