#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "rule_engine.hpp"
#include "topology.hpp"
#include "parser/yaml_parser.hpp"

namespace py = pybind11;
using namespace switchlint;

PYBIND11_MODULE(switchlint, m) {
    m.doc() = "switchlint Python bindings";

    py::enum_<Severity>(m, "Severity")
        .value("ERROR", Severity::ERROR)
        .value("WARN", Severity::WARN)
        .value("INFO", Severity::INFO)
        .export_values();

    py::class_<Violation>(m, "Violation")
        .def_readonly("rule_id", &Violation::rule_id)
        .def_readonly("message", &Violation::message)
        .def_readonly("severity", &Violation::severity)
        .def_readonly("stream_id", &Violation::stream_id)
        .def_readonly("node_id", &Violation::node_id)
        .def_readonly("port_id", &Violation::port_id)
        .def_readonly("source_line", &Violation::source_line)
        .def_readonly("source_file", &Violation::source_file);

    py::class_<Topology>(m, "Topology")
        .def_readonly("source_file", &Topology::source_file);

    m.def("parse", &parse_yaml, "Parse a YAML topology file");

    py::class_<RuleRegistry>(m, "RuleRegistry")
        .def(py::init<>())
        .def("run_all", &RuleRegistry::run_all)
        .def("run", &RuleRegistry::run)
        .def("explain", &RuleRegistry::explain)
        .def("list_rules", &RuleRegistry::list_rules);

    m.def("register_builtin_rules", [](RuleRegistry& reg, const RuleConfig& cfg, bool strict) {
        register_builtin_rules(reg, cfg, strict);
    }, py::arg("registry"), py::arg("config") = RuleConfig{}, py::arg("strict_unicast_fw") = false);
}
