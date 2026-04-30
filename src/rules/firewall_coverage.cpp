// src/rules/firewall_coverage.cpp
// FW001 — BMW failure mode #1: firewall coverage gap.
// For each stream, every switch port on every path src→dst must have a
// firewall "permit" entry whose stream_id matches the stream or whose
// dst_ip matches the stream's multicast_ip.
// Missing entry → ERROR.
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <algorithm>
#include <sstream>

namespace switchlint {

class FirewallCoverageRule : public Rule {
public:
    std::string id()          const override { return "FW001"; }
    std::string description() const override {
        return "Every switch port on a stream's path must have a matching firewall permit entry";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                for (const auto& path : paths) {
                    for (const auto& hop : path) {
                        if (hop.port_id.empty()) continue;

                        auto nit = topo.node_index.find(hop.node_id);
                        if (nit == topo.node_index.end()) continue;
                        if (nit->second->type != NodeType::SWITCH) continue;

                        std::string key = hop.node_id + "::" + hop.port_id;
                        auto pit = topo.port_index.find(key);
                        if (pit == topo.port_index.end()) continue;

                        const Port* port = pit->second;

                        bool covered = std::any_of(
                            port->firewall.begin(), port->firewall.end(),
                            [&](const FirewallEntry& fe) {
                                bool id_match  = fe.stream_id == stream.id;
                                bool ip_match  = (stream.multicast_ip != 0)
                                                 && (fe.dst_ip == stream.multicast_ip);
                                bool permitted = fe.action == "permit";
                                return (id_match || ip_match) && permitted;
                            });

                        if (!covered) {
                            std::ostringstream msg;
                            msg << "Stream " << stream.id
                                << ": no firewall permit entry on "
                                << hop.node_id << "::" << hop.port_id;
                            if (stream.multicast_ip != 0) {
                                uint32_t ip = stream.multicast_ip;
                                msg << " (multicast "
                                    << ((ip>>24)&0xFF) << '.' << ((ip>>16)&0xFF)
                                    << '.' << ((ip>>8)&0xFF) << '.' << (ip&0xFF)
                                    << ')';
                            }
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

std::unique_ptr<Rule> make_firewall_coverage_rule() {
    return std::make_unique<FirewallCoverageRule>();
}

} // namespace switchlint
