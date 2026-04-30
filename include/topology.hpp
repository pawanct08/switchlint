// include/topology.hpp
// Core data model for switchlint — automotive Ethernet topology representation.
// Covers ECUs, switches, ports (with VLAN membership + QoS), links, streams,
// multicast groups, and firewall entries.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace switchlint {

// ─── QoS / TSN ────────────────────────────────────────────────────────────────

/// Credit-Based Shaper parameters (IEEE 802.1Qav)
struct CBSConfig {
    uint32_t idle_slope_kbps{0};   // bandwidth reservation
    int32_t  send_slope_kbps{0};   // must be negative
    int32_t  hi_credit{0};         // should be > 0
    int32_t  lo_credit{0};         // should be < 0
};

/// Time-Aware Shaper parameters (IEEE 802.1Qbv) — MVP: presence check only
struct TASConfig {
    bool     gcl_present{false};   // gate control list defined?
    uint32_t cycle_time_ns{0};
};

struct PortQoS {
    std::optional<CBSConfig> cbs_class_a; // TSN class A (highest priority)
    std::optional<CBSConfig> cbs_class_b; // TSN class B
    std::optional<TASConfig> tas;
};

// ─── Firewall ─────────────────────────────────────────────────────────────────

struct FirewallEntry {
    std::string stream_id;   // which stream this entry covers
    uint32_t    src_ip{0};   // source IP (0 = wildcard)
    uint32_t    dst_ip{0};   // destination IP / multicast group
    uint16_t    dst_port{0}; // L4 port (0 = any)
    std::string action;      // "permit" | "deny"
};

// ─── MACsec ───────────────────────────────────────────────────────────────────

struct MACsecConfig {
    bool        enabled{false};
    uint32_t    sci{0};     // Secure Channel Identifier
    std::string key_id;     // which key material is configured
};

// ─── Port ─────────────────────────────────────────────────────────────────────

struct StormControl {
    uint32_t broadcast_limit_kbps{0};   // 0 = unlimited
    uint32_t multicast_limit_kbps{0};
};

struct Port {
    std::string                id;
    std::vector<uint16_t>      vlans;    // VLAN membership list
    uint16_t                   pvid{1};  // port VLAN ID — untagged frames use this
    bool                       tagged{true}; // true = 802.1Q tagged egress
    uint32_t                   line_rate_kbps{1000000}; // default 1Gbps
    PortQoS                    qos;
    MACsecConfig               macsec;
    std::vector<FirewallEntry> firewall;
    std::optional<StormControl> storm_control;
};

// ─── Node (ECU or Switch) ─────────────────────────────────────────────────────

enum class NodeType { ECU, SWITCH };

inline std::string to_string(NodeType t) {
    return t == NodeType::SWITCH ? "switch" : "ecu";
}

struct Node {
    std::string       id;
    NodeType          type{NodeType::ECU};
    std::vector<Port> ports;
};

// ─── Link ─────────────────────────────────────────────────────────────────────

struct Link {
    std::string src_node;
    std::string src_port;
    std::string dst_node;
    std::string dst_port;
};

// ─── Multicast ────────────────────────────────────────────────────────────────

struct MulticastGroup {
    uint32_t    group_ip;    // multicast group address (network byte order)
    std::string switch_id;   // switch that has this group configured
};

// ─── Stream ───────────────────────────────────────────────────────────────────

/// tsn_class encoding:
///   0 = Best-Effort (no shaper required)
///   1 = CBS Class A  (IEEE 802.1Qav)
///   2 = CBS Class B  (IEEE 802.1Qav)
///   3 = TAS          (IEEE 802.1Qbv)
struct Stream {
    std::string              id;
    std::string              src_node;
    std::vector<std::string> dst_nodes;
    uint16_t                 vlan_id{0};
    uint32_t                 multicast_ip{0}; // 0 = unicast
    uint8_t                  tsn_class{0};
    uint32_t                 bandwidth_kbps{0};
    uint8_t                  safety_level{0}; // 0=none, 1=QM, 2=ASIL-A, ...
    uint32_t                 max_latency_us{0}; // 0 = no constraint
};

// ─── SOME/IP Service ──────────────────────────────────────────────────────────

struct SomeIPService {
    uint16_t    service_id;
    uint16_t    instance_id;
    uint16_t    port;
    std::string provider_ecu;
};

// ─── Domains ──────────────────────────────────────────────────────────────────

struct Domain {
    std::string              id;
    std::vector<std::string> nodes;
};

// ─── Topology (root) ──────────────────────────────────────────────────────────

struct Topology {
    std::vector<Node>           nodes;
    std::vector<Link>           links;
    std::vector<Stream>         streams;
    std::vector<MulticastGroup> multicast_groups;
    std::vector<SomeIPService>  someip_services;
    std::vector<Domain>         domains;

    // Indexes populated by graph.cpp after parsing
    std::unordered_map<std::string, Node*> node_index;  // node_id → Node*
    std::unordered_map<std::string, Port*> port_index;  // "node_id::port_id" → Port*
    std::unordered_map<std::string, std::string> node_to_domain; // node_id → domain_id

    void build_indexes();
};

} // namespace switchlint
