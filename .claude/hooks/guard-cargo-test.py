#!/usr/bin/env python3
"""PreToolUse hook: block cargo test commands that risk OOM.

navra-server has 4 integration test binaries that each spawn real
server processes. Running them together (or even the full crate)
causes OOM. This hook enforces safe patterns:

ALLOWED:
  cargo test --workspace --exclude navra-server
  cargo test -p <any-crate-except-navra-server>
  cargo test -p navra-server --test <name> -- --test-threads=1

BLOCKED: everything else involving navra-server or bare workspace tests.
"""
import json, re, sys

try:
    data = json.load(sys.stdin)
except (json.JSONDecodeError, TypeError):
    sys.exit(0)

cmd = data.get("tool_input", {}).get("command", "")
if not cmd:
    sys.exit(0)

if "cargo test" not in cmd and "cargo nextest" not in cmd:
    sys.exit(0)

# --no-run only compiles, never spawns servers — always safe
if "--no-run" in cmd:
    sys.exit(0)

def block(reason):
    print(reason, file=sys.stderr)
    sys.exit(2)

has_threads_1 = "--test-threads=1" in cmd or "--test-threads 1" in cmd
has_workspace = "--workspace" in cmd
has_exclude_server = "--exclude navra-server" in cmd
has_p_server = "-p navra-server" in cmd
has_specific_crate = " -p " in cmd or " --package " in cmd

# Rule 1: workspace must exclude navra-server
if has_workspace and not has_exclude_server:
    block(
        "BLOCKED: must exclude navra-server from workspace tests.\n"
        "Use: cargo test --workspace --exclude navra-server"
    )

# Rule 2: navra-server must use --test <name> -- --test-threads=1
if has_p_server:
    # Must have BOTH --test <name> AND --test-threads=1
    # --test must be followed by a binary name, not --test-threads
    has_single_test = bool(re.search(r'--test\s+(?!threads)\w+', cmd))
    has_lib_only = "--lib" in cmd
    has_bin_only = bool(re.search(r'--bin\s+\w+', cmd))
    if not ((has_single_test or has_lib_only or has_bin_only) and has_threads_1):
        block(
            "BLOCKED: navra-server tests must use --test-threads=1.\n"
            "Use: cargo test -p navra-server -- --test-threads=1\n"
            "Or use 'just test-server' which runs each binary separately with cleanup.\n\n"
            "Individual binaries:\n"
            "  cargo test -p navra-server --test e2e -- --test-threads=1\n"
            "  cargo test -p navra-server --test adversarial_eval -- --test-threads=1\n"
            "  cargo test -p navra-server --test ifc_benchmark_e2e -- --test-threads=1\n"
            "  cargo test -p navra-server --test openshell_integration -- --test-threads=1\n"
            "  cargo test -p navra-server --lib -- --test-threads=1"
        )

# Rule 3: bare cargo test without -p or --workspace
if not has_specific_crate and not has_workspace:
    if cmd.strip().endswith("cargo test") or "cargo test --" in cmd or "cargo test -" in cmd:
        block(
            "BLOCKED: bare 'cargo test' runs all crates including navra-server.\n"
            "Use: cargo test --workspace --exclude navra-server"
        )

sys.exit(0)
