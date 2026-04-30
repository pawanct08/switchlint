// src/rules/tsn_cbs.cpp
// TSN001 — Credit-Based Shaper validation (IEEE 802.1Qav).
// For every stream with tsn_class 1 (Class A) or 2 (Class B):
//   • CBS config must be present on every switch port on the path
//   • idleSlope must be > 0
//   • sendSlope must be negative
//   • hiCredit must be > 0
//   • loCredit must be < 0
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class TSNCBSRule : public Rule {
public:
    std::string id()          const override { return "TSN001"; }
    std::string description() const override {
        return "CBS shaper must be configured with coherent parameters on all switch ports for TSN class-A/B streams";
    }

    std::string explain() const override {
        return "TSN001 — CBS Configuration Coherence\n"
               "IEEE 802.1Qav: The Credit-Based Shaper ensures bandwidth reservation for Class-A/B traffic.\n"
               "Incoherent parameters (e.g. non-negative sendSlope) will cause the hardware shaper\n"
               "to fail, resulting in jitter spikes that break control loop stability.\n"
               "Fix: Configure 'idle_slope_kbps' > 0 and 'send_slope_kbps' < 0 on the switch port.\n\n"
               "Related: LAT001 (latency budget), BW001 (oversubscription)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            if (stream.tsn_class < 1 || stream.tsn_class > 2) continue;

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
                        if (hop.port_id.empty()) continue;

                        auto nit = topo.node_index.find(hop.node_id);
                        if (nit == topo.node_index.end()) continue;
                        if (nit->second->type != NodeType::SWITCH) continue;

                        std::string key = hop.node_id + "::" + hop.port_id;
                        auto pit = topo.port_index.find(key);
                        if (pit == topo.port_index.end()) continue;

                        const Port* port = pit->second;
                        const auto& cbs  = (stream.tsn_class == 1)
                                           ? port->qos.cbs_class_a
                                           : port->qos.cbs_class_b;

                        auto emit = [&](Severity sev, const std::string& detail) {
                            std::ostringstream msg;
                            msg << "Stream " << stream.id
                                << " (class " << (int)stream.tsn_class << "): port "
                                << hop.node_id << "::" << hop.port_id
                                << " — " << detail;
                            Violation v;
                            v.severity  = sev;
                            v.rule_id   = id();
                            v.stream_id = stream.id;
                            v.node_id   = hop.node_id;
                            v.port_id   = hop.port_id;
                            v.message   = msg.str();
                            v.line_number = port->line_number;
                            violations.push_back(v);
                        };

                        if (!cbs.has_value()) {
                            emit(Severity::ERROR, "CBS class " +
                                 std::to_string(stream.tsn_class) + " not configured");
                            continue;
                        }

                        if (cbs->idle_slope_kbps == 0)
                            emit(Severity::ERROR, "idleSlope=0 (must be > 0)");

                        if (cbs->send_slope_kbps >= 0)
                            emit(Severity::ERROR, "sendSlope must be negative, got "
                                 + std::to_string(cbs->send_slope_kbps));

                        if (cbs->hi_credit <= 0)
                            emit(Severity::WARN, "hiCredit should be positive, got "
                                 + std::to_string(cbs->hi_credit));

                        if (cbs->lo_credit >= 0)
                            emit(Severity::WARN, "loCredit should be negative, got "
                                 + std::to_string(cbs->lo_credit));
                    }
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_tsn_cbs_rule() {
    return std::make_unique<TSNCBSRule>();
}

} // namespace switchlint
