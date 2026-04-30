// src/rules/vlan_storm_control.cpp
// VLAN003: Safety-critical VLANs must have storm control configured on ports.
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class VlanStormControlRule : public Rule {
public:
    std::string id()          const override { return "VLAN003"; }
    std::string description() const override {
        return "Safety-critical VLANs must have storm control enabled on switch ports";
    }

    std::string explain() const override {
        return "VLAN003 — VLAN Storm Control\n"
               "Automotive Safety Requirement: Storm control prevents broadcast/multicast traffic peaks\n"
               "from starving safety-critical streams sharing the same physical link.\n"
               "Without limits, a single malfunctioning ECU can bring down the entire control network.\n"
               "Fix: Add 'storm_control' configuration block to the reported switch port.\n\n"
               "Related: TOPO001 (redundancy), BW001 (oversubscription)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            if (stream.safety_level == 0) continue;

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                for (const auto& path : paths) {
                    for (const auto& hop : path) {
                        if (hop.port_id.empty()) continue;

                        // Only check switch ports
                        auto nit = topo.node_index.find(hop.node_id);
                        if (nit == topo.node_index.end() || nit->second->type != NodeType::SWITCH)
                            continue;

                        auto pit = topo.port_index.find(hop.node_id + "::" + hop.port_id);
                        if (pit == topo.port_index.end()) continue;

                        if (!pit->second->storm_control.has_value()) {
                            std::ostringstream msg;
                            msg << "Safety-critical stream " << stream.id << " (VLAN " << stream.vlan_id << ") "
                                << "traverses port " << hop.node_id << "::" << hop.port_id << " "
                                << "without storm control configured.";

                            Violation v;
                            v.severity  = Severity::WARN;
                            v.rule_id   = id();
                            v.stream_id = stream.id;
                            v.node_id   = hop.node_id;
                            v.port_id   = hop.port_id;
                            v.message   = msg.str();
                            v.line_number = pit->second->line_number;
                            violations.push_back(v);
                        }
                    }
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_vlan_storm_control_rule() {
    return std::make_unique<VlanStormControlRule>();
}

} // namespace switchlint
