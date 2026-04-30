// src/parser/yaml_parser.hpp
#pragma once
#include "topology.hpp"
#include <string>

namespace switchlint {
/// Parse a FLYNC-compatible YAML file and return a fully-indexed Topology.
/// Throws std::runtime_error on any schema or I/O error.
Topology parse_yaml(const std::string& path);
} // namespace switchlint
