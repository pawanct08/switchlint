// src/rules/hop_count.cpp
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class HopCountRule : public Rule {
public:
    explicit HopCountRule(const std::map<std::string, ConfigValue>& config) {
        if (config.count("max_hops")) {
            threshold_ = (int)std::get<int64_t>(config.at("max_hops"));
        }
    }

    std::string id()          const override { return "TOPO002"; }
    std::string description() const override {
        return "Streams must not exceed " + std::to_string(threshold_) + " switch hops to bound worst-case latency";
    }

    std::string explain() const override {
        return "TOPO002 — Max Switch Hops\n"
               "Standard: Automotive TSN Profiles. Latency bounds assume a max of 7 switch hops.\n"
               "Current threshold: " + std::to_string(threshold_) + "\n"
               "Excessive hops accumulate jitter and frame queuing delay beyond the budget\n"
               "modeled by standard TSN calculus, leading to non-deterministic arrival times.\n"
               "Fix: Re-route the stream through fewer switches or reorganize the network spine.\n\n"
               "Related: LAT001 (latency budget), TOPO001 (redundancy)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

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

                    if (actual_switches > threshold_) {
                        Violation v;
                        v.severity  = Severity::WARN;
                        v.rule_id   = id();
                        v.stream_id = stream.id;
                        v.message   = "Stream " + stream.id + ": " + std::to_string(actual_switches) + 
                                      " switch hops on path to " + dst + " — latency budget at risk";
                        v.source_line = stream.source_line;
                        v.source_file = topo.source_file;
                        violations.push_back(v);
                    }
                }
            }
        }
        return violations;
    }

private:
    int threshold_{7};
};

std::unique_ptr<Rule> make_hop_count_rule(const std::map<std::string, ConfigValue>& config) {
    return std::make_unique<HopCountRule>(config);
}

} // namespace switchlint
