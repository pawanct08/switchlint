// src/rules/someip_collision.cpp
// SD001: duplicate (service_id, instance_id) pairs across providers
// or same port on same ECU used by two services.
#include "rule_engine.hpp"
#include <unordered_map>
#include <unordered_set>
#include <sstream>

namespace switchlint {

class SomeIPCollisionRule : public Rule {
public:
    std::string id()          const override { return "SD001"; }
    std::string description() const override {
        return "Detect SOME/IP service ID collisions and ECU port conflicts";
    }

    std::vector<Violation> check(const Topology& topo) const override {
        std::vector<Violation> violations;

        // map of (service_id << 16 | instance_id) -> provider_ecu
        std::unordered_map<uint32_t, std::string> service_instance_map;
        // map of provider_ecu -> set of ports used
        std::unordered_map<std::string, std::unordered_set<uint16_t>> ecu_port_map;

        for (const auto& svc : topo.someip_services) {
            uint32_t key = (static_cast<uint32_t>(svc.service_id) << 16) | svc.instance_id;

            // Check rule 1: Duplicate (service_id, instance_id)
            auto it = service_instance_map.find(key);
            if (it != service_instance_map.end()) {
                if (it->second != svc.provider_ecu) {
                    std::ostringstream msg;
                    msg << "SOME/IP collision: service_id 0x" << std::hex << svc.service_id
                        << " instance_id 0x" << svc.instance_id << std::dec
                        << " provided by both " << it->second << " and " << svc.provider_ecu;
                    
                    Violation v;
                    v.severity = Severity::ERROR;
                    v.rule_id  = id();
                    v.node_id  = svc.provider_ecu;
                    v.message  = msg.str();
                    violations.push_back(v);
                }
            } else {
                service_instance_map[key] = svc.provider_ecu;
            }

            // Check rule 2: Same port on same ECU used by two services
            if (ecu_port_map[svc.provider_ecu].count(svc.port)) {
                std::ostringstream msg;
                msg << "SOME/IP port conflict: ECU " << svc.provider_ecu
                    << " uses L4 port " << svc.port << " for multiple services";
                
                Violation v;
                v.severity = Severity::ERROR;
                v.rule_id  = id();
                v.node_id  = svc.provider_ecu;
                v.message  = msg.str();
                violations.push_back(v);
            } else {
                ecu_port_map[svc.provider_ecu].insert(svc.port);
            }
        }

        return violations;
    }
};

std::unique_ptr<Rule> make_someip_collision_rule() {
    return std::make_unique<SomeIPCollisionRule>();
}

} // namespace switchlint
