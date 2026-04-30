// src/rules/tsn_tas.cpp
// TSN002 — Time-Aware Shaper gate control list presence check (IEEE 802.1Qbv).
// For every stream with tsn_class == 3 (TAS), every switch port on the path
// must have a TAS config with gcl_present=true and cycle_time_ns > 0.
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class TSNTASRule : public Rule {
public:
    std::string id()          const override { return "TSN002"; }
    std::string description() const override {
        return "TAS (time-aware shaper) gate control list must be present on switch ports for tsn_class=3 streams";
    }

    std::string explain() const override {
        return "TSN002 — TAS GCL Presence\n"
               "IEEE 802.1Qbv: Time-Aware Shaper (TAS) uses a Gate Control List (GCL) for time-slot scheduling.\n"
               "Without a GCL on every switch in the path, time-critical frames will face non-deterministic\n"
               "queuing delays, violating the hard-real-time constraints of the system.\n"
               "Fix: Set 'gcl_present: true' and define 'cycle_time_ns' in the port's TAS config.\n\n"
               "Related: TSN001 (CBS), LAT001 (latency budget)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            if (stream.tsn_class != 3) continue;

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                
                if (paths.empty()) {
                    Violation v;
                    v.severity  = Severity::WARN;
                    v.rule_id   = id();
                    v.stream_id = stream.id;
                    v.message   = "No physical path found from " + stream.src_node + " to " + dst;
                    v.source_line = stream.source_line;
                    v.source_file = topo.source_file;
                    violations.push_back(v);
                    continue;
                }

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

                        auto emit = [&](Severity sev, const std::string& detail) {
                            std::ostringstream msg;
                            msg << "Stream " << stream.id
                                << " (TAS): port "
                                << hop.node_id << "::" << hop.port_id
                                << " — " << detail;
                            Violation v;
                            v.severity  = sev;
                            v.rule_id   = id();
                            v.stream_id = stream.id;
                            v.node_id   = hop.node_id;
                            v.port_id   = hop.port_id;
                            v.message   = msg.str();
                            v.source_line = port->source_line;
                            v.source_file = topo.source_file;
                            violations.push_back(v);
                        };

                        if (!port->qos.tas.has_value()) {
                            emit(Severity::ERROR, "TAS config absent");
                            continue;
                        }

                        if (!port->qos.tas->gcl_present)
                            emit(Severity::ERROR, "gcl_present=false — no gate control list");

                        if (port->qos.tas->cycle_time_ns == 0)
                            emit(Severity::WARN, "cycle_time_ns=0 — TAS cycle not configured");
                    }
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_tsn_tas_rule(const std::map<std::string, ConfigValue>& config) {
    (void)config;
    return std::make_unique<TSNTASRule>();
}

} // namespace switchlint
