// src/rules/builtin_rules.cpp
// Wires all built-in rules into the RuleRegistry.
#include "rule_engine.hpp"

namespace switchlint {

// Forward declarations of factory functions
std::unique_ptr<Rule> make_vlan_membership_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_vlan_tagging_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_multicast_group_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_tsn_cbs_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_tsn_tas_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_firewall_coverage_rule(const std::map<std::string, ConfigValue>& config, bool strict_unicast_fw);
std::unique_ptr<Rule> make_bandwidth_oversubscription_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_someip_collision_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_redundancy_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_hop_count_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_orphan_detection_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_macsec_validation_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_latency_budget_rule(const std::map<std::string, ConfigValue>& config);
std::unique_ptr<Rule> make_vlan_storm_control_rule(const std::map<std::string, ConfigValue>& config);

void register_builtin_rules(RuleRegistry& registry, 
                            const RuleConfig& config,
                            bool strict_unicast_fw) {
    auto get_cfg = [&](const std::string& id) {
        auto it = config.find(id);
        return (it != config.end()) ? it->second : std::map<std::string, ConfigValue>{};
    };

    registry.register_rule(make_vlan_membership_rule(get_cfg("VLAN001")));
    registry.register_rule(make_vlan_tagging_rule(get_cfg("VLAN002")));
    registry.register_rule(make_multicast_group_rule(get_cfg("MC001")));
    registry.register_rule(make_tsn_cbs_rule(get_cfg("TSN001")));
    registry.register_rule(make_tsn_tas_rule(get_cfg("TSN002")));
    registry.register_rule(make_firewall_coverage_rule(get_cfg("FW001"), strict_unicast_fw));
    registry.register_rule(make_bandwidth_oversubscription_rule(get_cfg("BW001")));
    registry.register_rule(make_someip_collision_rule(get_cfg("SD001")));
    registry.register_rule(make_redundancy_rule(get_cfg("TOPO001")));
    registry.register_rule(make_hop_count_rule(get_cfg("TOPO002")));
    registry.register_rule(make_orphan_detection_rule(get_cfg("ORPH001")));
    registry.register_rule(make_macsec_validation_rule(get_cfg("SEC001")));
    registry.register_rule(make_latency_budget_rule(get_cfg("LAT001")));
    registry.register_rule(make_vlan_storm_control_rule(get_cfg("VLAN003")));
}

} // namespace switchlint
