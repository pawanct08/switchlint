// src/rules/macsec_validation.cpp
#include "rule_engine.hpp"
#include "path_resolver.hpp"
#include <sstream>

namespace switchlint {

class MACsecValidationRule : public Rule {
public:
    std::string id()          const override { return "SEC001"; }
    std::string description() const override {
        return "Cross-domain streams must be protected by MACsec on boundary links";
    }

    std::string explain() const override {
        return "SEC001 — MACsec Security Boundary\n"
               "Standard: IEEE 802.1AE. MACsec provides hardware-level encryption between switches.\n"
               "Cross-domain streams (e.g. Infotainment to ADAS) are high-risk targets for spoofing.\n"
               "Without link-layer encryption, an attacker can inject malicious control frames.\n"
               "Fix: Add 'macsec: {enabled: true}' to both endpoints of the boundary link.\n\n"
               "Related: FW001 (firewall), ORPH001 (orphan detection)";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        for (const auto& stream : topo.streams) {
            std::string src_domain = "";
            if (topo.node_to_domain.count(stream.src_node)) {
                src_domain = topo.node_to_domain.at(stream.src_node);
            }

            for (const auto& dst : stream.dst_nodes) {
                std::string dst_domain = "";
                if (topo.node_to_domain.count(dst)) {
                    dst_domain = topo.node_to_domain.at(dst);
                }

                // Rule: If source domain != destination domain, boundary links must have MACsec
                if (!src_domain.empty() && !dst_domain.empty() && src_domain != dst_domain) {
                    auto paths = resolve_stream_paths(stream, dst, topo);
                    for (const auto& path : paths) {
                        // A path is a sequence of {node, port}
                        // Pairs (path[0], path[1]), (path[2], path[3]), ... are physical links
                        for (size_t i = 0; i + 1 < path.size(); i += 2) {
                            const auto& hop1 = path[i];
                            const auto& hop2 = path[i+1];
                            
                            std::string dom1 = "";
                            if (topo.node_to_domain.count(hop1.node_id)) dom1 = topo.node_to_domain.at(hop1.node_id);
                            
                            std::string dom2 = "";
                            if (topo.node_to_domain.count(hop2.node_id)) dom2 = topo.node_to_domain.at(hop2.node_id);
                            
                            if (!dom1.empty() && !dom2.empty() && dom1 != dom2) {
                                // Domain boundary crossed on this link!
                                auto get_port = [&](const std::string& node_id, const std::string& port_id) -> const Port* {
                                    std::string key = node_id + "::" + port_id;
                                    auto it = topo.port_index.find(key);
                                    return (it != topo.port_index.end()) ? it->second : nullptr;
                                };
                                
                                const Port* p1 = get_port(hop1.node_id, hop1.port_id);
                                const Port* p2 = get_port(hop2.node_id, hop2.port_id);
                                
                                bool p1_ok = p1 && p1->macsec.enabled;
                                bool p2_ok = p2 && p2->macsec.enabled;
                                
                                if (!p1_ok || !p2_ok) {
                                    std::ostringstream msg;
                                    msg << "Domain boundary crossing (" << dom1 << " -> " << dom2 << ") detected on link: "
                                        << hop1.node_id << "::" << hop1.port_id << " <-> "
                                        << hop2.node_id << "::" << hop2.port_id << ". "
                                        << "Both link endpoints must have MACsec enabled for cross-domain streams.";
                                    
                                    Violation v;
                                    v.severity  = Severity::ERROR;
                                    v.rule_id   = id();
                                    v.stream_id = stream.id;
                                    v.node_id   = hop1.node_id; // Keep node/port as primary reference point
                                    v.port_id   = hop1.port_id;
                                    v.message   = msg.str();
                                    v.source_line = p1 ? p1->source_line : stream.source_line;
                                    v.source_file = topo.source_file;
                                    violations.push_back(v);
                                }
                            }
                        }
                    }
                }
            }
        }

        return violations;
    }
};

std::unique_ptr<Rule> make_macsec_validation_rule(const std::map<std::string, ConfigValue>& config) {
    (void)config;
    return std::make_unique<MACsecValidationRule>();
}

} // namespace switchlint
