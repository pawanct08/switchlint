// src/rules/redundancy.cpp
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class RedundancyRule : public Rule {
public:
    std::string id()          const override { return "TOPO001"; }
    std::string description() const override {
        return "Safety-critical streams (safety_level > 0) must have at least two redundant physical paths";
    }

    std::string explain() const override {
        return "TOPO001 — Redundancy Requirement\n"
               "Standard: ISO 26262 ASIL-D. Safety-critical systems require fail-operational networks.\n"
               "A single physical path for ASIL traffic is a single point of failure (SPOF);\n"
               "a link break will result in loss of control for safety-critical functions.\n"
               "Fix: Add at least one additional physical 'link' connecting the source and destination.\n\n"
               "Related: TOPO002 (hop count), VLAN003 (storm control)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            if (stream.safety_level == 0) continue;

            for (const auto& dst : stream.dst_nodes) {
                auto paths = resolve_stream_paths(stream, dst, topo);
                if (paths.size() < 2) {
                    Violation v;
                    v.severity  = Severity::WARN;
                    v.rule_id   = id();
                    v.stream_id = stream.id;
                    v.message   = "Stream " + stream.id + " (safety_level=" + std::to_string((int)stream.safety_level) +
                                  ") has only " + std::to_string(paths.size()) + " path(s) to " + dst + 
                                  ". Redundant path is required for safety.";
                    v.source_line = stream.source_line;
                    v.source_file = topo.source_file;
                    violations.push_back(v);
                }
            }
        }
        return violations;
    }
};

std::unique_ptr<Rule> make_redundancy_rule(const std::map<std::string, ConfigValue>& config) {
    (void)config;
    return std::make_unique<RedundancyRule>();
}

} // namespace switchlint
