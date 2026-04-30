// src/rules/rule_registry.cpp
// Owns all Rule instances and dispatches validation runs.
#include "rule_engine.hpp"
#include <stdexcept>

namespace switchlint {

void RuleRegistry::register_rule(std::unique_ptr<Rule> rule) {
    rules_.push_back(std::move(rule));
}

std::vector<Violation> RuleRegistry::run_all(const Topology& topo) const {
    std::vector<Violation> all;
    for (const auto& rule : rules_) {
        auto v = rule->check(topo);
        all.insert(all.end(), v.begin(), v.end());
    }
    return all;
}

std::vector<Violation> RuleRegistry::run(const std::string& rule_id,
                                         const Topology&    topo) const {
    for (const auto& rule : rules_) {
        if (rule->id() == rule_id) return rule->check(topo);
    }
    throw std::runtime_error("Unknown rule id: " + rule_id);
}

std::vector<std::pair<std::string,std::string>> RuleRegistry::list_rules() const {
    std::vector<std::pair<std::string,std::string>> out;
    for (const auto& r : rules_)
        out.emplace_back(r->id(), r->description());
    return out;
}

std::string RuleRegistry::explain(const std::string& rule_id) const {
    for (const auto& r : rules_) {
        if (r->id() == rule_id) return r->explain();
    }
    return "Unknown rule ID: " + rule_id;
}

} // namespace switchlint
