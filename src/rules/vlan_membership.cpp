// src/rules/vlan_membership.cpp
// VLAN001 — for every stream with a vlan_id, every port on every physical path
// src→dst must have that VLAN in its membership list.
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <algorithm>
#include <sstream>

namespace switchlint {

class VlanMembershipRule : public Rule {
public:
    std::string id()          const override { return "VLAN001"; }
    std::string description() const override {
        return "Every port on a stream's path must carry the stream's VLAN";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            if (stream.vlan_id == 0) continue; // no VLAN required

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);

                if (paths.empty()) {
                    Violation v;
                    v.severity  = Severity::WARN;
                    v.rule_id   = id();
                    v.stream_id = stream.id;
                    v.message   = "No physical path found from " + stream.src_node
                                  + " to " + dst;
                    violations.push_back(v);
                    continue;
                }

                for (const auto& path : paths) {
                    for (const auto& hop : path) {
                        if (hop.port_id.empty()) continue; // source node — no entry port

                        auto nit = topo.node_index.find(hop.node_id);
                        if (nit != topo.node_index.end() && nit->second->type == NodeType::ECU) continue;

                        std::string key = hop.node_id + "::" + hop.port_id;
                        auto it = topo.port_index.find(key);
                        if (it == topo.port_index.end()) continue;

                        const Port* port = it->second;
                        bool has_vlan = std::find(port->vlans.begin(),
                                                  port->vlans.end(),
                                                  stream.vlan_id) != port->vlans.end();
                        if (!has_vlan) {
                            std::ostringstream msg;
                            msg << "Stream " << stream.id << ": port "
                                << hop.node_id << "::" << hop.port_id
                                << " missing VLAN " << stream.vlan_id;
                            Violation v;
                            v.severity  = Severity::ERROR;
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

// Self-registration helper called by register_builtin_rules()
std::unique_ptr<Rule> make_vlan_membership_rule() {
    return std::make_unique<VlanMembershipRule>();
}

} // namespace switchlint
