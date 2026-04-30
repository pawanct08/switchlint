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
std::unique_ptr<Rule> make_firewall_coverage_rule(bool strict_unicast_fw);
std::unique_ptr<Rule> make_bandwidth_oversubscription_rule();
std::unique_ptr<Rule> make_someip_collision_rule();
std::unique_ptr<Rule> make_redundancy_rule();
std::unique_ptr<Rule> make_hop_count_rule();
std::unique_ptr<Rule> make_orphan_detection_rule();
std::unique_ptr<Rule> make_macsec_validation_rule();
std::unique_ptr<Rule> make_latency_budget_rule();

void register_builtin_rules(RuleRegistry& registry, bool strict_unicast_fw) {
    registry.register_rule(make_vlan_membership_rule());
    registry.register_rule(make_vlan_tagging_rule());
    registry.register_rule(make_multicast_group_rule());
    registry.register_rule(make_tsn_cbs_rule());
    registry.register_rule(make_tsn_tas_rule());
    registry.register_rule(make_firewall_coverage_rule(strict_unicast_fw));
    registry.register_rule(make_bandwidth_oversubscription_rule());
    registry.register_rule(make_someip_collision_rule());
    registry.register_rule(make_redundancy_rule());
    registry.register_rule(make_hop_count_rule());
    registry.register_rule(make_orphan_detection_rule());
    registry.register_rule(make_macsec_validation_rule());
    registry.register_rule(make_latency_budget_rule());
}

} // namespace switchlint
