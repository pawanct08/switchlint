# switchlint — Automotive Ethernet Switch Config Validator

> **Automotive Ethernet Validation Tooling** — catches common configuration errors: missing firewall rules, unrouted multicast streams, TSN stream misconfiguration, and VLAN membership gaps — *before any hardware is touched*.

---

## Problem Statement

Industry experience has identified several concrete failure modes in Automotive Ethernet switch projects:

| # | Failure Mode |
|---|---|
| 1 | ARXML describes ECUs, not the vehicle — switch config hand-derived per project |
| 2 | Format chain: ARXML → proprietary → YANG → vendor binary — each step manual and lossy |
| 3 | No topology model → firewall rules, VLANs, multicast groups written by hand per switch |
| 4 | No unified debug/DLT config |
| 5 | No standardised management interface |
| 6 | TSN feature over-escalation — features configured that nobody uses |

**switchlint** addresses failure modes 1, 3, and 6 with a linter that validates a topology description against a rule set — CI-friendly, exit-code-clean.

---

## Architecture

```
switchlint/
├── include/
│   ├── topology.hpp        ← data model (Node, Port, Stream, Link, …)
│   ├── rule_engine.hpp     ← Rule interface + RuleRegistry
│   └── diagnostic.hpp      ← Violation + Severity
├── src/
│   ├── parser/
│   │   └── yaml_parser.cpp ← FLYNC-compatible YAML ingestion
│   ├── topology/
│   │   ├── graph.cpp       ← index builder
│   │   └── path_resolver.cpp ← DFS path enumeration (VLAN-agnostic)
│   ├── rules/
│   │   ├── vlan_membership.cpp  → VLAN001
│   │   ├── vlan_tagging.cpp     → VLAN002
│   │   ├── multicast_group.cpp  → MC001
│   │   ├── tsn_cbs.cpp          → TSN001
│   │   ├── tsn_tas.cpp          → TSN002
│   │   └── firewall_coverage.cpp→ FW001
│   ├── report/
│   │   ├── text_reporter.cpp   ← ANSI-coloured human output
│   │   └── json_reporter.cpp   ← structured JSON for CI dashboards
│   └── cli/main.cpp
├── tests/
│   ├── fixtures/           ← valid + broken YAML topologies
│   └── rules/              ← GoogleTest per-rule unit tests
├── CMakeLists.txt
└── switchlint_ci.py        ← Python CI wrapper
```

---

## Built-in Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `VLAN001` | ERROR | Every port on a stream's physical path must carry the stream's VLAN |
| `VLAN002` | WARN  | Untagged egress port PVID must match the stream's VLAN |
| `MC001`   | ERROR | Every switch on a multicast stream's path must have the group statically configured |
| `TSN001`  | ERROR/WARN | CBS shaper must be present with coherent parameters (idleSlope > 0, sendSlope < 0, credit signs) |
| `TSN002`  | ERROR/WARN | TAS gate control list must be present with non-zero cycle time |
| `FW001`   | ERROR | Every switch port on a stream's path must have a matching firewall `permit` entry |

---

## Build

### Prerequisites

- CMake ≥ 3.18
- C++17 compiler (GCC 10+, Clang 12+, MSVC 2019+)
- Internet access for FetchContent (yaml-cpp, nlohmann/json, GoogleTest)

### Linux / macOS

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Windows (Visual Studio)

```powershell
cmake -B build
cmake --build build --config Release
```

---

## Usage

```bash
# Basic validation — exits 1 on any ERROR
switchlint topology.yaml

# JSON output for CI dashboards
switchlint topology.yaml --format json --output report.json

# Run only specific rules
switchlint topology.yaml --rules VLAN001,FW001

# Fail on warnings too
switchlint topology.yaml --fail-on-warn

# List all available rules
switchlint --list-rules
```

### Example output

```
[ERROR] Stream cam_front: port SW1::p2 missing VLAN 100
[ERROR] Stream radar_rear: switch SW2 has no multicast group for 239.1.1.5
[WARN]  Stream audio_main (class 1): port SW1::p3 — hiCredit should be positive, got 0

Summary: 2 error(s), 1 warning(s), 0 info(s)
```

---

## Input Format (FLYNC-compatible YAML)

```yaml
ecus:
  - id: ZCU_front
    type: ecu
    ports:
      - id: eth0
        vlans: [100, 200]
        tagged: true

  - id: SW1
    type: switch
    ports:
      - id: p1
        vlans: [100, 200]
        tagged: true
        qos:
          cbs_class_a:
            idle_slope_kbps: 50000
            send_slope_kbps: -950000
            hi_credit: 1500
            lo_credit: -28500
        firewall:
          - stream_id: cam_front
            dst_ip: "239.1.1.1"
            action: permit

links:
  - {src: ZCU_front, src_port: eth0, dst: SW1, dst_port: p1}

streams:
  - id: cam_front
    src: ZCU_front
    dst: [ECU_display]
    vlan_id: 100
    multicast_ip: "239.1.1.1"
    tsn_class: 1        # 0=BE, 1=CBS-A, 2=CBS-B, 3=TAS
    bandwidth_kbps: 50000

multicast_groups:
  - group_ip: "239.1.1.1"
    switch_id: SW1
```

---

## Running Tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

---

## CI Integration

```bash
# GitHub Actions / any CI — fails the step on violations
python switchlint_ci.py topology.yaml --fail-on-warn

# With JSON report artifact
python switchlint_ci.py topology.yaml --format json --output switchlint_report.json
```

---

## Adding a Custom Rule

1. Create `src/rules/my_rule.cpp` implementing the `Rule` interface:

```cpp
#include "rule_engine.hpp"

namespace switchlint {
class MyRule : public Rule {
public:
    std::string id()          const override { return "CUSTOM001"; }
    std::string description() const override { return "My custom check"; }
    std::vector<Violation> check(const Topology& topo) const override {
        // ... your logic here
        return {};
    }
};
std::unique_ptr<Rule> make_my_rule() { return std::make_unique<MyRule>(); }
}
```

2. Add `make_my_rule()` call to `src/rules/builtin_rules.cpp`.
3. Add the `.cpp` file to `CMakeLists.txt` under `switchlint_core`.

---

## Design Notes

- **Path resolution is VLAN-agnostic** by design. The DFS runs on the physical link graph first; VLAN membership is checked as a separate pass so that each port with a missing VLAN generates its own precise violation rather than a single "no path found" message.
- **Firewall rule matches** on either `stream_id` or `dst_ip` (multicast group address) to accommodate both stream-tagged and group-tagged ACL styles.
- **Exit codes**: `0` = clean, `1` = violations present, `2` = fatal error (parse failure, unknown rule).
