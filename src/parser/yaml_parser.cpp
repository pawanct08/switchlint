// src/parser/yaml_parser.cpp
// Ingests FLYNC-compatible YAML into a Topology struct.
// Fails fast on schema violations via descriptive exceptions.
#include "yaml_parser.hpp"

#include <yaml-cpp/yaml.h>
#include <stdexcept>
#include <sstream>
#ifndef _WIN32
#  include <arpa/inet.h>   // inet_pton — Linux/Unix
#endif

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#endif

namespace switchlint {

// ─── helpers ──────────────────────────────────────────────────────────────────

static uint32_t parse_ipv4(const std::string& s, bool require_multicast = false) {
    struct in_addr addr{};
#ifdef _WIN32
    if (inet_pton(AF_INET, s.c_str(), &addr) != 1)
#else
    if (inet_pton(AF_INET, s.c_str(), &addr) != 1)
#endif
        throw std::runtime_error("Invalid IPv4 address: " + s);
    
    uint32_t ip = ntohl(addr.s_addr);
    if (require_multicast && ((ip >> 28) != 0xE)) {
        throw std::runtime_error("Invalid multicast IP (must be 224.0.0.0/4): " + s);
    }
    return ip;  // store in host byte order
}

static CBSConfig parse_cbs(const YAML::Node& n) {
    CBSConfig c;
    if (n["idle_slope_kbps"]) c.idle_slope_kbps = n["idle_slope_kbps"].as<uint32_t>();
    if (n["send_slope_kbps"]) c.send_slope_kbps = n["send_slope_kbps"].as<int32_t>();
    if (n["hi_credit"])       c.hi_credit        = n["hi_credit"].as<int32_t>();
    if (n["lo_credit"])       c.lo_credit        = n["lo_credit"].as<int32_t>();
    return c;
}

static Port parse_port(const YAML::Node& n) {
    if (!n["id"]) throw std::runtime_error("Port missing 'id' field");
    Port p;
    p.id     = n["id"].as<std::string>();
    p.tagged = n["tagged"] ? n["tagged"].as<bool>() : true;
    p.pvid   = n["pvid"]   ? n["pvid"].as<uint16_t>() : 1;
    if (n["line_rate_kbps"]) p.line_rate_kbps = n["line_rate_kbps"].as<uint32_t>();

    if (n["vlans"]) {
        for (const auto& v : n["vlans"])
            p.vlans.push_back(v.as<uint16_t>());
    }

    // QoS / TSN
    if (n["qos"]) {
        const auto& q = n["qos"];
        if (q["cbs_class_a"]) p.qos.cbs_class_a = parse_cbs(q["cbs_class_a"]);
        if (q["cbs_class_b"]) p.qos.cbs_class_b = parse_cbs(q["cbs_class_b"]);
        if (q["tas"]) {
            TASConfig t;
            t.gcl_present   = q["tas"]["gcl_present"] ? q["tas"]["gcl_present"].as<bool>() : false;
            t.cycle_time_ns = q["tas"]["cycle_time_ns"] ? q["tas"]["cycle_time_ns"].as<uint32_t>() : 0;
            p.qos.tas = t;
        }
    }

    // Firewall entries
    if (n["firewall"]) {
        for (const auto& fe : n["firewall"]) {
            FirewallEntry entry;
            entry.stream_id = fe["stream_id"] ? fe["stream_id"].as<std::string>() : "";
            entry.src_ip    = fe["src_ip"]    ? parse_ipv4(fe["src_ip"].as<std::string>()) : 0;
            entry.dst_ip    = fe["dst_ip"]    ? parse_ipv4(fe["dst_ip"].as<std::string>()) : 0;
            entry.dst_port  = fe["dst_port"]  ? fe["dst_port"].as<uint16_t>() : 0;
            entry.action    = fe["action"]    ? fe["action"].as<std::string>() : "permit";
            p.firewall.push_back(entry);
        }
    }

    return p;
}

static Node parse_node(const YAML::Node& n) {
    if (!n["id"]) throw std::runtime_error("Node missing 'id' field");
    Node node;
    node.id = n["id"].as<std::string>();

    std::string type_str = n["type"] ? n["type"].as<std::string>() : "ecu";
    node.type = (type_str == "switch") ? NodeType::SWITCH : NodeType::ECU;

    if (n["ports"]) {
        for (const auto& p : n["ports"])
            node.ports.push_back(parse_port(p));
    }

    return node;
}

// ─── public API ───────────────────────────────────────────────────────────────

Topology parse_yaml(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error(std::string("YAML parse error: ") + e.what());
    }

    Topology topo;

    // ECUs / switches — both live under "ecus" key for FLYNC compat
    if (root["ecus"]) {
        for (const auto& n : root["ecus"])
            topo.nodes.push_back(parse_node(n));
    }
    // Also accept top-level "nodes" key
    if (root["nodes"]) {
        for (const auto& n : root["nodes"])
            topo.nodes.push_back(parse_node(n));
    }

    // Links
    if (root["links"]) {
        for (const auto& l : root["links"]) {
            Link link;
            // Accept both {src, src_port} and {src, dst} shorthand
            link.src_node = l["src"].as<std::string>();
            link.src_port = l["src_port"].as<std::string>();
            link.dst_node = l["dst"].as<std::string>();
            link.dst_port = l["dst_port"].as<std::string>();
            topo.links.push_back(link);
        }
    }

    // Streams
    if (root["streams"]) {
        for (const auto& s : root["streams"]) {
            Stream stream;
            stream.id       = s["id"].as<std::string>();
            stream.src_node = s["src"].as<std::string>();

            if (s["dst"]) {
                for (const auto& d : s["dst"])
                    stream.dst_nodes.push_back(d.as<std::string>());
            }

            stream.vlan_id        = s["vlan_id"]        ? s["vlan_id"].as<uint16_t>()        : 0;
            stream.tsn_class      = s["tsn_class"]      ? s["tsn_class"].as<uint8_t>()       : 0;
            stream.bandwidth_kbps = s["bandwidth_kbps"] ? s["bandwidth_kbps"].as<uint32_t>() : 0;
            stream.safety_level   = s["safety_level"]   ? s["safety_level"].as<uint8_t>()    : 0;

            if (s["multicast_ip"] && !s["multicast_ip"].IsNull()) {
                stream.multicast_ip = parse_ipv4(s["multicast_ip"].as<std::string>(), true);
            }

            topo.streams.push_back(stream);
        }
    }

    // Multicast groups
    if (root["multicast_groups"]) {
        for (const auto& mg : root["multicast_groups"]) {
            MulticastGroup g;
            g.group_ip  = parse_ipv4(mg["group_ip"].as<std::string>(), true);
            g.switch_id = mg["switch_id"].as<std::string>();
            topo.multicast_groups.push_back(g);
        }
    }

    // SOME/IP Services
    if (root["someip_services"]) {
        for (const auto& sv : root["someip_services"]) {
            SomeIPService s;
            s.service_id   = sv["service_id"].as<uint16_t>();
            s.instance_id  = sv["instance_id"].as<uint16_t>();
            s.port         = sv["port"].as<uint16_t>();
            s.provider_ecu = sv["provider_ecu"].as<std::string>();
            topo.someip_services.push_back(s);
        }
    }

    topo.build_indexes();
    return topo;
}

} // namespace switchlint
