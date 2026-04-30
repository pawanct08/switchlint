// tests/rules/test_firewall.cpp
#include <gtest/gtest.h>
#include "rule_engine.hpp"
#include "topology.hpp"
#include "../src/parser/yaml_parser.hpp"
#include <algorithm>

static std::vector<switchlint::Violation>
filter(const std::vector<switchlint::Violation>& all, const std::string& rule) {
    std::vector<switchlint::Violation> out;
    std::copy_if(all.begin(), all.end(), std::back_inserter(out),
        [&](const auto& v){ return v.rule_id == rule; });
    return out;
}

#ifndef FIXTURE_DIR
#  define FIXTURE_DIR "tests/fixtures"
#endif

TEST(FW001, ValidTopologyProducesNoViolations) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/valid_topology.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "FW001");
    EXPECT_TRUE(v.empty()) << "No FW001 violations expected on valid topology";
}

TEST(FW001, MissingPermitEntryProducesError) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/broken_firewall.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "FW001");
    ASSERT_FALSE(v.empty()) << "Expected FW001 violation on SW1::p2";
    EXPECT_EQ(v[0].severity, switchlint::Severity::ERROR);

    bool found_p2 = std::any_of(v.begin(), v.end(),
        [](const auto& x){ return x.node_id == "SW1" && x.port_id == "p2"; });
    EXPECT_TRUE(found_p2) << "Violation should point at SW1::p2";
}

TEST(FW001, DenyEntryDoesNotSatisfyCoverage) {
    switchlint::Topology topo;

    { switchlint::Node n; n.id="SRC"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    { switchlint::Node sw; sw.id="SW1"; sw.type=switchlint::NodeType::SWITCH;
      switchlint::Port swp; swp.id="p1"; swp.vlans={100}; swp.tagged=true;
      // Only a "deny" entry — FW001 must still flag this
      switchlint::FirewallEntry fe;
      fe.stream_id="s1"; fe.action="deny";
      swp.firewall.push_back(fe);
      sw.ports.push_back(swp); topo.nodes.push_back(sw); }

    { switchlint::Node n; n.id="DST"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    topo.links.push_back({"SRC","eth0","SW1","p1"});
    topo.links.push_back({"SW1","p1","DST","eth0"});

    switchlint::Stream s; s.id="s1"; s.src_node="SRC"; s.dst_nodes={"DST"};
    s.vlan_id=100; s.tsn_class=0;
    topo.streams.push_back(s);
    topo.build_indexes();

    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "FW001");
    ASSERT_FALSE(v.empty()) << "Deny entry should not satisfy FW001 permit requirement";
}

TEST(FW001, PermitByMulticastIpMatchesStream) {
    switchlint::Topology topo;

    { switchlint::Node n; n.id="SRC"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    { switchlint::Node sw; sw.id="SW1"; sw.type=switchlint::NodeType::SWITCH;
      switchlint::Port swp; swp.id="p1"; swp.vlans={100}; swp.tagged=true;
      switchlint::FirewallEntry fe;
      // Match by dst_ip (multicast group), not stream_id
      fe.dst_ip  = (239u<<24)|(1u<<16)|(1u<<8)|1u; // 239.1.1.1 in host order
      fe.action  = "permit";
      swp.firewall.push_back(fe);
      sw.ports.push_back(swp); topo.nodes.push_back(sw); }

    { switchlint::Node n; n.id="DST"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    topo.links.push_back({"SRC","eth0","SW1","p1"});
    topo.links.push_back({"SW1","p1","DST","eth0"});

    switchlint::Stream s; s.id="s1"; s.src_node="SRC"; s.dst_nodes={"DST"};
    s.vlan_id=100; s.tsn_class=0;
    s.multicast_ip = (239u<<24)|(1u<<16)|(1u<<8)|1u;
    topo.streams.push_back(s);
    topo.build_indexes();

    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "FW001");
    EXPECT_TRUE(v.empty()) << "Permit by matching dst_ip should satisfy FW001";
}

TEST(FW001, StreamIdOnlyMatchWithPermit) {
    switchlint::Topology topo;

    { switchlint::Node n; n.id="SRC"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    { switchlint::Node sw; sw.id="SW1"; sw.type=switchlint::NodeType::SWITCH;
      switchlint::Port swp; swp.id="p1"; swp.vlans={100}; swp.tagged=true;
      switchlint::FirewallEntry fe;
      fe.stream_id="s1"; fe.action="permit";
      swp.firewall.push_back(fe);
      sw.ports.push_back(swp); topo.nodes.push_back(sw); }

    { switchlint::Node n; n.id="DST"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    topo.links.push_back({"SRC","eth0","SW1","p1"});
    topo.links.push_back({"SW1","p1","DST","eth0"});

    switchlint::Stream s; s.id="s1"; s.src_node="SRC"; s.dst_nodes={"DST"};
    s.vlan_id=100; s.tsn_class=0;
    topo.streams.push_back(s);
    topo.build_indexes();

    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "FW001");
    EXPECT_TRUE(v.empty()) << "stream_id permit match should satisfy FW001";
}
