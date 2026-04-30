// tests/rules/test_tsn.cpp
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

TEST(TSN001, BestEffortStreamSkipped) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/broken_vlan.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    EXPECT_TRUE(filter(reg.run_all(topo), "TSN001").empty());
}

TEST(TSN001, MissingCBSConfigProducesError) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/broken_tsn.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "TSN001");
    ASSERT_FALSE(v.empty());
    EXPECT_EQ(v[0].severity, switchlint::Severity::ERROR);
}

TEST(TSN001, ValidCBSProducesNoViolation) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/valid_topology.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    EXPECT_TRUE(filter(reg.run_all(topo), "TSN001").empty());
}

TEST(TSN001, ZeroIdleSlopeProducesError) {
    switchlint::Topology topo;
    { switchlint::Node n; n.id="SRC"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    { switchlint::Node sw; sw.id="SW1"; sw.type=switchlint::NodeType::SWITCH;
      switchlint::Port swp; swp.id="p1"; swp.vlans={100}; swp.tagged=true;
      switchlint::CBSConfig cbs; cbs.idle_slope_kbps=0; cbs.send_slope_kbps=-950000;
      cbs.hi_credit=1500; cbs.lo_credit=-100; swp.qos.cbs_class_a=cbs;
      sw.ports.push_back(swp); topo.nodes.push_back(sw); }

    { switchlint::Node n; n.id="DST"; n.type=switchlint::NodeType::ECU;
      switchlint::Port p; p.id="eth0"; p.vlans={100}; p.tagged=true;
      n.ports.push_back(p); topo.nodes.push_back(n); }

    topo.links.push_back({"SRC","eth0","SW1","p1"});
    topo.links.push_back({"SW1","p1","DST","eth0"});

    switchlint::Stream s;
    s.id="s1"; s.src_node="SRC"; s.dst_nodes={"DST"}; s.vlan_id=100; s.tsn_class=1;
    topo.streams.push_back(s);
    topo.build_indexes();

    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "TSN001");
    bool found = std::any_of(v.begin(), v.end(),
        [](const auto& x){ return x.message.find("idleSlope=0") != std::string::npos; });
    EXPECT_TRUE(found);
}

TEST(TSN002, MissingTASConfigProducesError) {
    switchlint::Topology topo;
    for (auto [id, t] : std::vector<std::pair<std::string,switchlint::NodeType>>{
            {"SRC",switchlint::NodeType::ECU}, {"DST",switchlint::NodeType::ECU}}) {
        switchlint::Node n; n.id=id; n.type=t;
        switchlint::Port p; p.id="eth0"; p.vlans={300}; p.tagged=true;
        n.ports.push_back(p); topo.nodes.push_back(n);
    }
    { switchlint::Node sw; sw.id="SW1"; sw.type=switchlint::NodeType::SWITCH;
      switchlint::Port swp; swp.id="p1"; swp.vlans={300}; swp.tagged=true;
      sw.ports.push_back(swp); topo.nodes.push_back(sw); }

    topo.links.push_back({"SRC","eth0","SW1","p1"});
    topo.links.push_back({"SW1","p1","DST","eth0"});

    switchlint::Stream s; s.id="s_tas"; s.src_node="SRC"; s.dst_nodes={"DST"};
    s.vlan_id=300; s.tsn_class=3; topo.streams.push_back(s);
    topo.build_indexes();

    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto v = filter(reg.run_all(topo), "TSN002");
    ASSERT_FALSE(v.empty());
    EXPECT_EQ(v[0].severity, switchlint::Severity::ERROR);
}
