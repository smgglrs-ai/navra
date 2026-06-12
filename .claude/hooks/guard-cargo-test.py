#!/usr/bin/env python3
"""PreToolUse hook: block cargo test commands that risk OOM.

Rules:
- `cargo test --workspace` MUST include `--test-threads=1` OR `--exclude navra-server`
- `cargo test -p navra-server` MUST include `--test-threads=1`
- Bare `cargo test` (implicit workspace) MUST include `--test-threads=1` or a -p flag
- Single-crate tests for non-server crates are fine

Input: JSON on stdin with tool_input.command
Output: exit 0 = allow, exit 2 = block (reason on stderr)
"""
import json, sys

try:
    data = json.load(sys.stdin)
except (json.JSONDecodeError, TypeError):
    sys.exit(0)

cmd = data.get("tool_input", {}).get("command", "")
if not cmd:
    sys.exit(0)

if "cargo test" not in cmd and "cargo nextest" not in cmd:
    sys.exit(0)

has_threads_1 = "--test-threads=1" in cmd or "--test-threads 1" in cmd
has_workspace = "--workspace" in cmd
has_exclude_server = "--exclude navra-server" in cmd
has_p_server = "-p navra-server" in cmd
has_specific_crate = " -p " in cmd or " --package " in cmd

def block(reason):
    print(reason, file=sys.stderr)
    sys.exit(2)

if has_workspace and not has_threads_1 and not has_exclude_server:
    block(
        "BLOCKED: cargo test --workspace without --test-threads=1 will OOM.\n"
        "Use: cargo test --workspace -- --test-threads=1\n"
        "  OR: cargo test --workspace --exclude navra-server"
    )

if has_p_server and not has_threads_1:
    block(
        "BLOCKED: navra-server tests must use --test-threads=1.\n"
        "Use: cargo test -p navra-server -- --test-threads=1"
    )

if "cargo test" in cmd and not has_specific_crate and not has_workspace:
    if "cargo test --" in cmd or cmd.strip().endswith("cargo test"):
        if not has_threads_1:
            block(
                "BLOCKED: bare 'cargo test' in workspace root runs all crates.\n"
                "Use: cargo test --workspace -- --test-threads=1\n"
                "  OR: cargo test -p <specific-crate>"
            )

sys.exit(0)
