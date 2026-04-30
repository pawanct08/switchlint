// src/rules/latency_budget.cpp
// LAT001: End-to-end latency budget validation for CBS Class-A streams.
// Based on IEEE 802.1Qav worst-case delay formulas.
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

static constexpr uint32_t MAX_FRAME_BITS = 12176; // 1522 bytes standard Ethernet frame

class LatencyBudgetRule : public Rule {
public:
    std::string id()          const override { return "LAT001"; }
    std::string description() const override {
        return "CBS Class-A streams must not exceed their configured end-to-end latency budget (IEEE 802.1Qav)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            // LAT001 only applies to CBS Class-A with a defined budget
            if (stream.tsn_class != 1 || stream.max_latency_us == 0) continue;

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                for (const auto& path : paths) {
                    uint64_t total_delay_us = 0;
                    bool path_coherent = true;

                    for (const auto& hop : path) {
                        if (hop.port_id.empty()) continue;

                        auto nit = topo.node_index.find(hop.node_id);
                        if (nit != topo.node_index.end() && nit->second->type != NodeType::SWITCH)
                            continue;

                        auto pit = topo.port_index.find(hop.node_id + "::" + hop.port_id);
                        if (pit == topo.port_index.end()) continue;

                        const auto& cbs_opt = pit->second->qos.cbs_class_a;
                        if (cbs_opt.has_value() && cbs_opt->idle_slope_kbps > 0) {
                            // IEEE 802.1Qav simplified worst-case per-hop delay
                            total_delay_us += (MAX_FRAME_BITS * 1000ULL) / cbs_opt->idle_slope_kbps;
                        } else {
                            // If CBS is missing or invalid on a path port, we can't calculate latency reliably
                            path_coherent = false;
                            break;
                        }
                    }

                    if (path_coherent && total_delay_us > stream.max_latency_us) {
                        std::ostringstream msg;
                        msg << "Stream " << stream.id << " exceeds latency budget: "
                            << total_delay_us << "us calculated vs " << stream.max_latency_us << "us limit"
                            << " on path to " << dst;

                        Violation v;
                        v.severity  = Severity::ERROR;
                        v.rule_id   = id();
                        v.stream_id = stream.id;
                        v.message   = msg.str();
                        violations.push_back(v);
                    }
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_latency_budget_rule() {
    return std::make_unique<LatencyBudgetRule>();
}

} // namespace switchlint
