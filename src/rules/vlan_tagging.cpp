// src/rules/vlan_tagging.cpp
// VLAN002 — tagged/untagged egress consistency check.
// A port that is the egress point to a destination ECU must have tagged=false
// only if the ECU expects untagged frames (i.e., the stream's VLAN equals the
// port's PVID).  If tagged=false but vlan_id != pvid, frames arrive without
// a VLAN tag and the ECU cannot determine the VLAN — flagged as WARN.
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class VlanTaggingRule : public Rule {
public:
    std::string id()          const override { return "VLAN002"; }
    std::string description() const override {
        return "Tagged/untagged egress consistency: untagged egress port pvid must match stream VLAN";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            if (stream.vlan_id == 0) continue;

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                for (const auto& path : paths) {
                    for (const auto& hop : path) {
                        if (hop.port_id.empty()) continue;

                        std::string key = hop.node_id + "::" + hop.port_id;
                        auto it = topo.port_index.find(key);
                        if (it == topo.port_index.end()) continue;

                        const Port* port = it->second;
                        // Only flag untagged egress where PVID != stream VLAN
                        if (!port->tagged && port->pvid != stream.vlan_id) {
                            std::ostringstream msg;
                            msg << "Stream " << stream.id << ": port "
                                << hop.node_id << "::" << hop.port_id
                                << " is untagged (pvid=" << port->pvid
                                << ") but stream uses VLAN " << stream.vlan_id
                                << " — frame arrives without VLAN tag";
                            Violation v;
                            v.severity  = Severity::WARN;
                            v.rule_id   = id();
                            v.stream_id = stream.id;
                            v.node_id   = hop.node_id;
                            v.port_id   = hop.port_id;
                            v.message   = msg.str();
                            violations.push_back(v);
                        }
                    }
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_vlan_tagging_rule() {
    return std::make_unique<VlanTaggingRule>();
}

} // namespace switchlint
