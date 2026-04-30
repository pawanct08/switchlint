#!/usr/bin/env python3
"""
switchlint_ci.py — Python CI wrapper for switchlint.
Runs the switchlint binary and exits with a non-zero code on violations.

Usage:
    python switchlint_ci.py topology.yaml [--binary path/to/switchlint]
                                          [--format text|json]
                                          [--fail-on-warn]
                                          [--rules RULE1,RULE2]
"""
import argparse
import subprocess
import sys
import os


def find_binary(hint: str) -> str:
    """Resolve switchlint binary — search build dir if not explicit."""
    if hint:
        return hint
    candidates = [
        os.path.join("build", "switchlint"),
        os.path.join("build", "Release", "switchlint.exe"),
        os.path.join("build", "Debug",   "switchlint.exe"),
        os.path.join("build", "switchlint.exe"),
        "switchlint",
        "switchlint.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return "switchlint"   # last resort — rely on PATH


def main() -> int:
    parser = argparse.ArgumentParser(description="switchlint CI wrapper")
    parser.add_argument("topology",       help="Path to topology YAML file")
    parser.add_argument("--binary",       default="", help="Path to switchlint binary")
    parser.add_argument("--format",       default="text", choices=["text", "json"])
    parser.add_argument("--fail-on-warn", action="store_true")
    parser.add_argument("--rules",        default="", help="Comma-separated rule ids")
    parser.add_argument("--output",       default="", help="Write JSON report to file")
    args = parser.parse_args()

    binary = find_binary(args.binary)
    cmd = [binary, args.topology, "--format", args.format]

    if args.fail_on_warn:
        cmd.append("--fail-on-warn")
    if args.rules:
        cmd += ["--rules", args.rules]
    if args.output:
        cmd += ["--output", args.output]

    print(f"[switchlint-ci] Running: {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd)

    if result.returncode == 0:
        print("[switchlint-ci] ✓ No violations found", flush=True)
    elif result.returncode == 1:
        print("[switchlint-ci] ✗ Violations detected — see output above", flush=True)
    else:
        print(f"[switchlint-ci] ✗ switchlint exited with code {result.returncode}",
              flush=True)

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
