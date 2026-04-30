// src/rules/orphan_detection.cpp
#include "rule_engine.hpp"
#include <unordered_set>

namespace switchlint {

class OrphanDetectionRule : public Rule {
public:
    std::string id()          const override { return "ORPH001"; }
    std::string description() const override {
        return "Detect isolated nodes and invalid stream endpoints";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        // 1. Nodes with no links -> INFO
        std::unordered_set<std::string> nodes_with_links;
        for (const auto& link : topo.links) {
            nodes_with_links.insert(link.src_node);
            nodes_with_links.insert(link.dst_node);
        }

        for (const auto& node : topo.nodes) {
            if (nodes_with_links.find(node.id) == nodes_with_links.end()) {
                Violation v;
                v.severity = Severity::INFO;
                v.rule_id  = id();
                v.node_id  = node.id;
                v.message  = "Node " + node.id + " is isolated (has no links)";
                violations.push_back(v);
            }
        }

        // 2. Streams whose src_node or dst_nodes don't exist in node_index -> ERROR
        for (const auto& stream : topo.streams) {
            if (topo.node_index.find(stream.src_node) == topo.node_index.end()) {
                Violation v;
                v.severity  = Severity::ERROR;
                v.rule_id   = id();
                v.stream_id = stream.id;
                v.message   = "Stream " + stream.id + " source node '" + stream.src_node + "' does not exist";
                violations.push_back(v);
            }

            for (const auto& dst : stream.dst_nodes) {
                if (topo.node_index.find(dst) == topo.node_index.end()) {
                    Violation v;
                    v.severity  = Severity::ERROR;
                    v.rule_id   = id();
                    v.stream_id = stream.id;
                    v.message   = "Stream " + stream.id + " destination node '" + dst + "' does not exist";
                    violations.push_back(v);
                }
            }
        }

        return violations;
    }
};

std::unique_ptr<Rule> make_orphan_detection_rule() {
    return std::make_unique<OrphanDetectionRule>();
}

} // namespace switchlint
