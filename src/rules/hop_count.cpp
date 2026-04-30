// src/rules/hop_count.cpp
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class HopCountRule : public Rule {
public:
    std::string id()          const override { return "TOPO002"; }
    std::string description() const override {
        return "Streams must not exceed 7 switch hops to bound worst-case latency";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;
        const int threshold = 7;

        for (const auto& stream : topo.streams) {
            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                for (const auto& path : paths) {
                    int switch_hops = 0;
                    for (const auto& hop : path) {
                        auto it = topo.node_index.find(hop.node_id);
                        if (it != topo.node_index.end() && it->second->type == NodeType::SWITCH) {
                            switch_hops++;
                        }
                    }
                    // DFS generates path as pairs: {current, exit}, {next, entry}, {next, exit}...
                    // Therefore, every switch node on the path appears exactly twice: 
                    // once for the entry port and once for the exit port.
                    int actual_switches = switch_hops / 2;

                    if (actual_switches > threshold) {
                        Violation v;
                        v.severity  = Severity::WARN;
                        v.rule_id   = id();
                        v.stream_id = stream.id;
                        v.message   = "Stream " + stream.id + ": " + std::to_string(actual_switches) + 
                                      " switch hops on path to " + dst + " — latency budget at risk";
                        violations.push_back(v);
                    }
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_hop_count_rule() {
    return std::make_unique<HopCountRule>();
}

} // namespace switchlint
