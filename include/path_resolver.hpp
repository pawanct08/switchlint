// include/path_resolver.hpp
// Physical-graph path resolution for switchlint.
// Paths are enumerated by DFS on the link graph; VLAN filtering is applied
// AFTER path resolution so that the VLAN-membership rule can produce
// per-port violation messages instead of just "no path found".
#pragma once

#include "topology.hpp"
#include <string>
#include <vector>

namespace switchlint {

/// One hop on a resolved path: the node and the port through which we enter it.
struct PathHop {
    std::string node_id;
    std::string port_id;  // entry port on this node (empty for the source)
};

using Path = std::vector<PathHop>;

/// Find all simple (cycle-free) paths between src_node and dst_node in the
/// physical link graph (VLAN-agnostic — caller applies VLAN checks separately).
std::vector<Path> resolve_paths(const std::string& src_node,
                                const std::string& dst_node,
                                const Topology&    topo);

/// Convenience wrapper: resolve paths for a stream to one of its destinations.
std::vector<Path> resolve_stream_paths(const Stream&   stream,
                                       const std::string& dst_node,
                                       const Topology& topo);

} // namespace switchlint
