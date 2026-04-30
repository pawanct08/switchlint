// src/report/sarif_reporter.cpp
#include "sarif_reporter.hpp"
#include <nlohmann/json.hpp>
#include <set>

using json = nlohmann::json;

namespace switchlint {

static std::string severity_to_level(Severity s) {
    switch (s) {
        case Severity::ERROR:   return "error";
        case Severity::WARN:    return "warning";
        case Severity::INFO:    return "note";
        default:                return "note";
    }
}

void print_sarif_report(const std::vector<Violation>& violations, std::ostream& os) {
    json sarif = {
        {"$schema", "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"},
        {"version", "2.1.0"},
        {"runs", json::array({
            {
                {"tool", {
                    {"driver", {
                        {"name", "switchlint"},
                        {"informationUri", "https://github.com/pawanct08/switchlint"},
                        {"rules", json::array()}
                    }}
                }},
                {"results", json::array()}
            }
        })}
    };

    auto& rules = sarif["runs"][0]["tool"]["driver"]["rules"];
    auto& results = sarif["runs"][0]["results"];

    // Use a set to track which rules we've added to the tool metadata
    std::set<std::string> seen_rules;

    for (const auto& v : violations) {
        if (seen_rules.find(v.rule_id) == seen_rules.end()) {
            rules.push_back({
                {"id", v.rule_id},
                {"shortDescription", {{"text", v.rule_id}}} // Detailed description could be added here if we had access to RuleRegistry
            });
            seen_rules.insert(v.rule_id);
        }

        json result = {
            {"ruleId", v.rule_id},
            {"level", severity_to_level(v.severity)},
            {"message", {{"text", v.message}}},
            {"locations", json::array({
                {
                    {"physicalLocation", {
                        {"artifactLocation", {
                            {"uri", "topology.yaml"} // Ideally we'd pass the actual input filename here
                        }},
                        {"region", {
                            {"startLine", v.line_number}
                        }}
                    }}
                }
            })}
        };

        // Add logical location info if available
        if (!v.node_id.empty()) {
            result["locations"][0]["logicalLocations"] = json::array({{
                {"name", v.node_id},
                {"kind", "node"}
            }});
        }

        results.push_back(result);
    }

    os << sarif.dump(2) << std::endl;
}

} // namespace switchlint
