// include/rule_engine.hpp
// Pluggable rule engine interface and registry for switchlint.
#pragma once

#include "diagnostic.hpp"
#include "topology.hpp"

#include <memory>
#include <string>
#include <vector>

namespace switchlint {

/// Abstract base class for all validation rules.
class Rule {
public:
    virtual ~Rule() = default;

    /// Short unique identifier, e.g. "VLAN001"
    virtual std::string id() const = 0;
    virtual std::string description() const = 0;

    /// Detailed explanation of the rule, including standard references.
    virtual std::string explain() const { return "No detailed explanation available."; }

    /// Run this rule against the topology and return any violations.
    virtual std::vector<Violation> check(const Topology& topo) const = 0;
};

/// Owns all registered rules and dispatches checks.
class RuleRegistry {
public:
    void register_rule(std::unique_ptr<Rule> rule);

    /// Run every registered rule.
    std::vector<Violation> run_all(const Topology& topo) const;

    /// Run a single rule by its id().
    std::vector<Violation> run(const std::string& rule_id,
                               const Topology& topo) const;

    /// Returns all registered rule ids + descriptions.
    std::vector<std::pair<std::string, std::string>> list_rules() const;

    /// Returns detailed explanation for a given rule.
    std::string explain(const std::string& rule_id) const;

private:
    std::vector<std::unique_ptr<Rule>> rules_;
};

/// Populate the registry with all built-in rules.
void register_builtin_rules(RuleRegistry& registry, bool strict_unicast_fw = false);

} // namespace switchlint
