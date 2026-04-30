// tests/rules/test_vlan.cpp
// GoogleTest unit tests for VLAN001 (membership) and VLAN002 (tagging).
#include <gtest/gtest.h>
#include "rule_engine.hpp"
#include "topology.hpp"
#include "../src/parser/yaml_parser.hpp"

#include <algorithm>
#include <filesystem>

// Helper: find violations by rule_id
static std::vector<switchlint::Violation>
filter(const std::vector<switchlint::Violation>& all, const std::string& rule) {
    std::vector<switchlint::Violation> out;
    std::copy_if(all.begin(), all.end(), std::back_inserter(out),
        [&](const auto& v){ return v.rule_id == rule; });
    return out;
}

// Path to test fixtures — set by CMake via compile definition FIXTURE_DIR
#ifndef FIXTURE_DIR
#  define FIXTURE_DIR "tests/fixtures"
#endif

// ─── VLAN001 ──────────────────────────────────────────────────────────────────

TEST(VLAN001, ValidTopologyProducesNoViolations) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/valid_topology.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto violations = filter(reg.run_all(topo), "VLAN001");
    EXPECT_TRUE(violations.empty())
        << "Unexpected VLAN001 violations on valid topology";
}

TEST(VLAN001, MissingVlanOnPortProducesError) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/broken_vlan.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto violations = filter(reg.run_all(topo), "VLAN001");

    ASSERT_FALSE(violations.empty()) << "Expected at least one VLAN001 violation";

    // All violations should be ERRORs
    for (const auto& v : violations)
        EXPECT_EQ(v.severity, switchlint::Severity::ERROR);

    // At least one violation on SW1::p2 (the port with missing VLAN 100)
    bool found_p2 = std::any_of(violations.begin(), violations.end(),
        [](const auto& v){ return v.node_id == "SW1" && v.port_id == "p2"; });
    EXPECT_TRUE(found_p2) << "Expected violation on SW1::p2";
}

TEST(VLAN001, StreamIdPresentInViolation) {
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/broken_vlan.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto violations = filter(reg.run_all(topo), "VLAN001");

    ASSERT_FALSE(violations.empty());
    EXPECT_EQ(violations[0].stream_id, "cam_front");
}

// ─── VLAN002 ──────────────────────────────────────────────────────────────────

TEST(VLAN002, UntaggedPortWithMatchingPvidIsOk) {
    // valid_topology.yaml: ECU_display::eth0 is untagged with pvid=100,
    // stream cam_front uses VLAN 100 — no VLAN002 violation expected.
    auto topo = switchlint::parse_yaml(std::string(FIXTURE_DIR) + "/valid_topology.yaml");
    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto violations = filter(reg.run_all(topo), "VLAN002");
    EXPECT_TRUE(violations.empty())
        << "Expected no VLAN002 violations when pvid matches stream VLAN";
}

TEST(VLAN002, UntaggedPortWithMismatchedPvidIsWarned) {
    // Build an in-memory topology with a mismatch
    switchlint::Topology topo;

    switchlint::Node src;
    src.id   = "SRC";
    src.type = switchlint::NodeType::ECU;
    switchlint::Port sp;
    sp.id     = "eth0";
    sp.vlans  = {100};
    sp.tagged = true;
    src.ports.push_back(sp);
    topo.nodes.push_back(src);

    switchlint::Node sw;
    sw.id   = "SW1";
    sw.type = switchlint::NodeType::SWITCH;
    switchlint::Port swp1, swp2;
    swp1.id     = "p1"; swp1.vlans = {100}; swp1.tagged = true;
    swp2.id     = "p2"; swp2.vlans = {100};
    swp2.tagged = false; swp2.pvid  = 200; // mismatch: stream VLAN=100, pvid=200
    sw.ports.push_back(swp1);
    sw.ports.push_back(swp2);
    topo.nodes.push_back(sw);

    switchlint::Node dst;
    dst.id   = "DST";
    dst.type = switchlint::NodeType::ECU;
    switchlint::Port dp;
    dp.id = "eth0"; dp.vlans = {100}; dp.tagged = true;
    dst.ports.push_back(dp);
    topo.nodes.push_back(dst);

    topo.links.push_back({"SRC", "eth0", "SW1", "p1"});
    topo.links.push_back({"SW1", "p2",   "DST", "eth0"});

    switchlint::Stream s;
    s.id       = "test_stream";
    s.src_node = "SRC";
    s.dst_nodes= {"DST"};
    s.vlan_id  = 100;
    topo.streams.push_back(s);

    topo.build_indexes();

    switchlint::RuleRegistry reg;
    switchlint::register_builtin_rules(reg);
    auto violations = filter(reg.run_all(topo), "VLAN002");

    ASSERT_FALSE(violations.empty()) << "Expected a VLAN002 warning for pvid mismatch";
    EXPECT_EQ(violations[0].severity, switchlint::Severity::WARN);
    EXPECT_EQ(violations[0].node_id,  "SW1");
    EXPECT_EQ(violations[0].port_id,  "p2");
}
