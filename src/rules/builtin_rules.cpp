// src/rules/builtin_rules.cpp
// Wires all built-in rules into the RuleRegistry.
#include "rule_engine.hpp"

namespace switchlint {

// Forward declarations of factory functions
std::unique_ptr<Rule> make_vlan_membership_rule();
std::unique_ptr<Rule> make_vlan_tagging_rule();
std::unique_ptr<Rule> make_multicast_group_rule();
std::unique_ptr<Rule> make_tsn_cbs_rule();
std::unique_ptr<Rule> make_tsn_tas_rule();
std::unique_ptr<Rule> make_firewall_coverage_rule();

void register_builtin_rules(RuleRegistry& registry) {
    registry.register_rule(make_vlan_membership_rule());
    registry.register_rule(make_vlan_tagging_rule());
    registry.register_rule(make_multicast_group_rule());
    registry.register_rule(make_tsn_cbs_rule());
    registry.register_rule(make_tsn_tas_rule());
    registry.register_rule(make_firewall_coverage_rule());
}

} // namespace switchlint
