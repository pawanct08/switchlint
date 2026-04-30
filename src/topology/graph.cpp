// src/topology/graph.cpp
// Builds the node/port indexes after the topology is parsed.
#include "topology.hpp"
#include <stdexcept>

namespace switchlint {

void Topology::build_indexes() {
    node_index.clear();
    port_index.clear();

    for (auto& node : nodes) {
        if (node_index.count(node.id)) {
            throw std::runtime_error("Duplicate node id: " + node.id);
        }
        node_index[node.id] = &node;

        for (auto& port : node.ports) {
            std::string key = node.id + "::" + port.id;
            if (port_index.count(key)) {
                throw std::runtime_error("Duplicate port key: " + key);
            }
            port_index[key] = &port;
        }
    }
}

} // namespace switchlint
