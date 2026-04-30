// src/topology/path_resolver.cpp
// DFS-based path enumeration on the physical link graph.
// Deliberately VLAN-agnostic: VLAN membership is validated as a separate rule
// so that we get precise per-port violation messages.
#include "path_resolver.hpp"

#include <unordered_set>

namespace switchlint {

static void dfs(const std::string&              current,
                const std::string&              target,
                const Topology&                 topo,
                std::unordered_set<std::string>& visited,
                Path&                           current_path,
                std::vector<Path>&              results)
{
    if (current == target) {
        results.push_back(current_path);
        return;
    }
    visited.insert(current);

    for (const auto& link : topo.links) {
        std::string next_node;
        std::string entry_port;
        std::string exit_port;

        if (link.src_node == current) {
            next_node  = link.dst_node;
            entry_port = link.dst_port;
            exit_port  = link.src_port;
        } else if (link.dst_node == current) {
            next_node  = link.src_node;
            entry_port = link.src_port;
            exit_port  = link.dst_port;
        } else {
            continue;
        }

        if (visited.count(next_node)) continue;

        current_path.push_back({current, exit_port});
        current_path.push_back({next_node, entry_port});
        dfs(next_node, target, topo, visited, current_path, results);
        current_path.pop_back();
        current_path.pop_back();
    }

    visited.erase(current);
}

std::vector<Path> resolve_paths(const std::string& src_node,
                                const std::string& dst_node,
                                const Topology&    topo)
{
    std::vector<Path>              results;
    Path                           current_path;
    std::unordered_set<std::string> visited;

    dfs(src_node, dst_node, topo, visited, current_path, results);
    return results;
}

std::vector<Path> resolve_stream_paths(const Stream&      stream,
                                       const std::string& dst_node,
                                       const Topology&    topo)
{
    return resolve_paths(stream.src_node, dst_node, topo);
}

} // namespace switchlint
