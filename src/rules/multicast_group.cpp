// src/rules/multicast_group.cpp
// MC001 — for each multicast stream, every switch on every path must have
// the group statically configured in the multicast_groups list.
// (IGMP-snooping dynamic learning is not modelled in the YAML — treat absence
//  of a static entry as an error.)
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <algorithm>
#include <sstream>

namespace switchlint {

class MulticastGroupRule : public Rule {
public:
    std::string id()          const override { return "MC001"; }
    std::string description() const override {
        return "Every switch on a multicast stream's path must have the group configured";
    }

    std::string explain() const override {
        return "MC001 — Multicast Forwarding Database (FDB) Miss\n"
               "Automotive switches typically use static multicast group configurations to prevent flooding.\n"
               "If a multicast stream traverses a switch that has no matching entry in its Multicast Groups\n"
               "table, the switch may either discard the frame or flood it to all ports, depending on its\n"
               "default policy. Both behaviors are unacceptable in a deterministic network.\n\n"
               "Related: FW001 (firewall)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            if (stream.multicast_ip == 0) continue; // unicast — skip

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                
                if (paths.empty()) {
                    Violation v;
                    v.severity  = Severity::WARN;
                    v.rule_id   = id();
                    v.stream_id = stream.id;
                    v.message   = "No physical path found from " + stream.src_node + " to " + dst;
                    v.line_number = stream.line_number;
                    violations.push_back(v);
                    continue;
                }

                for (const auto& path : paths) {
                    for (const auto& hop : path) {
                        auto nit = topo.node_index.find(hop.node_id);
                        if (nit == topo.node_index.end()) continue;
                        if (nit->second->type != NodeType::SWITCH) continue;

                        const std::string& sw_id = hop.node_id;
                        bool found = std::any_of(
                            topo.multicast_groups.begin(),
                            topo.multicast_groups.end(),
                            [&](const MulticastGroup& mg) {
                                return mg.switch_id == sw_id
                                    && mg.group_ip  == stream.multicast_ip;
                            });

                        if (!found) {
                            // Format IP as dotted-decimal for readability
                            uint32_t ip = stream.multicast_ip;
                            std::ostringstream ipstr;
                            ipstr << ((ip >> 24) & 0xFF) << '.'
                                  << ((ip >> 16) & 0xFF) << '.'
                                  << ((ip >>  8) & 0xFF) << '.'
                                  << ( ip        & 0xFF);

                            std::ostringstream msg;
                            msg << "Stream " << stream.id
                                << ": switch " << sw_id
                                << " has no multicast group for "
                                << ipstr.str();
                            Violation v;
                            v.severity  = Severity::ERROR;
                            v.rule_id   = id();
                            v.stream_id = stream.id;
                            v.node_id   = sw_id;
                            v.message   = msg.str();
                            v.line_number = nit->second->line_number;
                            violations.push_back(v);
                        }
                    }
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_multicast_group_rule() {
    return std::make_unique<MulticastGroupRule>();
}

} // namespace switchlint
