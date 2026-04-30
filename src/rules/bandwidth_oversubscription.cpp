// src/rules/bandwidth_oversubscription.cpp
// BW001: sum of all stream bandwidths sharing a switch port
// must not exceed port line rate * 0.75 for class-A CBS.
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <unordered_map>
#include <unordered_set>
#include <sstream>

namespace switchlint {

class BandwidthOversubscriptionRule : public Rule {
public:
    std::string id()          const override { return "BW001"; }
    std::string description() const override {
        return "Cumulative class-A stream bandwidth must not exceed 75% of switch port line rate";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        // port_key ("node::port") -> sum of class-A bandwidth_kbps
        std::unordered_map<std::string, uint64_t> port_bandwidth;
        // stream_id + "::" + port_key -> already counted?
        std::unordered_set<std::string> counted;

        for (const auto& stream : topo.streams) {
            if (stream.tsn_class != 1) continue; // Only care about Class-A
            if (stream.bandwidth_kbps == 0) continue;

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                for (const auto& path : paths) {
                    for (const auto& hop : path) {
                        if (hop.port_id.empty()) continue;

                        auto nit = topo.node_index.find(hop.node_id);
                        if (nit == topo.node_index.end()) continue;
                        if (nit->second->type != NodeType::SWITCH) continue;

                        std::string key = hop.node_id + "::" + hop.port_id;
                        std::string counted_key = stream.id + "::" + key;
                        if (!counted.count(counted_key)) {
                            port_bandwidth[key] += stream.bandwidth_kbps;
                            counted.insert(counted_key);
                        }
                    }
                }
            }
        }

        // Now check all switch ports against their line rate limit
        for (const auto& [key, total_bw] : port_bandwidth) {
            auto pit = topo.port_index.find(key);
            if (pit == topo.port_index.end()) continue;
            const Port* port = pit->second;

            uint64_t limit = static_cast<uint64_t>(port->line_rate_kbps * 0.75);
            if (total_bw > limit) {
                // We need the node ID and port ID for the violation. They are in the key.
                size_t sep = key.find("::");
                std::string node_id = key.substr(0, sep);
                std::string port_id = key.substr(sep + 2);

                std::ostringstream msg;
                msg << "Port " << key << " is oversubscribed by class-A streams: "
                    << total_bw << " kbps used, but limit is " << limit << " kbps (75% of "
                    << port->line_rate_kbps << ")";

                Violation v;
                v.severity = Severity::ERROR;
                v.rule_id  = id();
                v.node_id  = node_id;
                v.port_id  = port_id;
                v.message  = msg.str();
                violations.push_back(v);
            }
        }

        return violations;
    }
};

std::unique_ptr<Rule> make_bandwidth_oversubscription_rule() {
    return std::make_unique<BandwidthOversubscriptionRule>();
}

} // namespace switchlint
