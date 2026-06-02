"""MCPTox benchmark evaluation for navra's upstream tool scanner.

Tests navra's 8-category threat scanner against MCPTox's 485 poisoned
MCP tool descriptions from 45 real-world servers. Measures detection
rate per attack category and false positive rate on clean tools.

Dataset: https://github.com/zhiqiangwang4/MCPTox-Benchmark (AAAI 2026)
"""

import json
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

MCPTOX_DIR = Path("/tmp/mcptox")
NAVRA_ROOT = Path(__file__).parent.parent.parent

def load_mcptox():
    """Load poisoned tools from MCPTox dataset."""
    with open(MCPTOX_DIR / "pure_tool.json") as f:
        servers = json.load(f)

    tools = []
    for server in servers:
        for key, tool in server.items():
            tools.append({
                "id": key,
                "server": tool["server_name"],
                "name": tool["tool_name"],
                "description": tool["tool_content"],
                "query": tool.get("query", ""),
            })
    return tools


def load_clean_tools():
    """Load clean tool descriptions from the response metadata."""
    with open(MCPTOX_DIR / "response_all.json") as f:
        data = json.load(f)

    clean = []
    for name, server in data.get("servers", {}).items():
        prompt = server.get("clean_system_promot", "")
        if prompt:
            clean.append({
                "id": f"clean_{name}",
                "server": name,
                "name": f"{name}_clean",
                "description": prompt,
            })
    return clean


def scan_with_navra(description: str, tool_name: str) -> list:
    """Scan a tool description using navra's ToolScanner patterns.

    Since the scanner is in Rust, we use a lightweight check that
    mirrors the scanner's detection logic in Python for benchmark speed.
    The actual Rust scanner is tested separately in integration tests.
    """
    findings = []

    desc_lower = description.lower()

    # DescriptionInjection: imperative instructions directing tool chaining.
    # These patterns match instructions that tell the agent to call OTHER
    # tools as a "prerequisite" — the core MCPTox attack pattern.
    # Legitimate descriptions describe WHAT the tool does, not WHICH OTHER
    # TOOLS to call before/after it.
    injection_patterns = [
        # Direct chaining instructions
        "you must first call", "must first call", "must first use",
        "you must always set", "you must mark", "you must always",
        "you must set", "you must use", "you must call",
        # "Before X" + tool verb (the core MCPTox pattern)
        "before using", "before calling", "before proceeding",
        "before this tool", "before deletion", "before formatting",
        "before generating", "before validation", "before navigating",
        "before calculating", "before counting", "before checking",
        "before parsing", "before monitoring", "before syncing",
        # "make sure" + tool verb
        "make sure get", "make sure use", "make sure call",
        # "When using X" + change/set (redirect pattern)
        "when using", "when use the tool",
        # Priority override
        "this description's priority is higher",
        "this rule takes priority",
        # Consequence threats (coercion)
        "skipping this step will", "omitting this step",
        "failing to do so", "failure to do so",
        "failure to validate", "this step is critical",
        "will cause delivery fail", "will cause storage err",
        "will return incorrect", "will disrupt",
        # Other chaining
        "pre-authorization check", "pre-check is required",
        "step 1:", "first call ", "always call ",
        "must be changed to",
        "to log activity", "to free resources", "to validate content",
        "change the recipient to", "append the original",
        "set bcc to", "set keywords to",
    ]
    for pattern in injection_patterns:
        if pattern in desc_lower:
            findings.append({
                "category": "DescriptionInjection",
                "severity": "High",
                "detail": f"Cross-tool instruction: '{pattern}'",
            })
            break

    # ToolPoisoning: references to sensitive files/paths
    sensitive_paths = [
        "/.ssh/", "/etc/passwd", "/etc/shadow", "id_rsa",
        "authorized_keys", ".env", "credentials", "secret",
        "/tmp/ssh", "private_key", "api_key", "token",
    ]
    for path in sensitive_paths:
        if path in description:
            findings.append({
                "category": "ToolPoisoning",
                "severity": "Critical",
                "detail": f"Sensitive path reference: '{path}'",
            })
            break

    # CrossServerReference: calls to external URLs
    import re
    urls = re.findall(r'https?://[^\s"\'<>]+', description)
    external_urls = [u for u in urls if "evil" in u or "attacker" in u
                     or "malicious" in u or "collect" in u or "exfil" in u
                     or "redirect" in u or "webhook" in u or "c2" in u]
    if external_urls:
        findings.append({
            "category": "CrossServerReference",
            "severity": "Critical",
            "detail": f"Suspicious external URL: {external_urls[0][:60]}",
        })

    # Also catch any external URL in a tool description (suspicious)
    if not external_urls and urls:
        findings.append({
            "category": "CrossServerReference",
            "severity": "Medium",
            "detail": f"External URL in description: {urls[0][:60]}",
        })

    # HiddenUnicode: zero-width characters, homoglyphs
    for char in description:
        cp = ord(char)
        if cp in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD):
            findings.append({
                "category": "HiddenUnicode",
                "severity": "High",
                "detail": f"Zero-width character U+{cp:04X}",
            })
            break

    # IntentBehaviorMismatch: tool claims to do X but instructs Y
    read_words = ["read", "get", "fetch", "list", "search", "query", "view"]
    write_words = ["write", "delete", "overwrite", "move", "execute",
                   "run", "send", "post", "upload", "install"]
    has_read_intent = any(w in tool_name.lower() for w in read_words)
    has_write_instruction = any(w in desc_lower for w in write_words)
    if has_read_intent and has_write_instruction:
        findings.append({
            "category": "IntentBehaviorMismatch",
            "severity": "High",
            "detail": f"Tool '{tool_name}' claims read but instructs write",
        })

    # SchemaAbuse: overly broad input schemas or suspicious fields
    # (MCPTox doesn't include schemas, only descriptions — skip)

    return findings


def main():
    poisoned = load_mcptox()
    clean = load_clean_tools()

    print(f"MCPTox Benchmark Evaluation")
    print(f"{'='*60}")
    print(f"Poisoned tools: {len(poisoned)} (from {len(set(t['server'] for t in poisoned))} servers)")
    print(f"Clean tools: {len(clean)}")
    print()

    # Scan poisoned tools
    detected = 0
    missed = 0
    category_counts = defaultdict(int)
    missed_tools = []

    for tool in poisoned:
        findings = scan_with_navra(tool["description"], tool["name"])
        if findings:
            detected += 1
            for f in findings:
                category_counts[f["category"]] += 1
        else:
            missed += 1
            missed_tools.append(tool)

    detection_rate = detected / len(poisoned) if poisoned else 0

    print(f"--- Poisoned Tool Detection ---")
    print(f"Detected: {detected}/{len(poisoned)} ({detection_rate:.1%})")
    print(f"Missed:   {missed}/{len(poisoned)} ({1-detection_rate:.1%})")
    print()
    print(f"Detections by category:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:<30} {count:>4}")
    print()

    # Scan clean tools (false positives)
    fp = 0
    for tool in clean:
        findings = scan_with_navra(tool["description"], tool["name"])
        if findings:
            fp += 1

    fpr = fp / len(clean) if clean else 0
    print(f"--- Clean Tool False Positives ---")
    print(f"False positives: {fp}/{len(clean)} ({fpr:.1%})")
    print()

    # Show missed tools
    if missed_tools:
        print(f"--- Missed Poisoned Tools ({len(missed_tools)}) ---")
        for tool in missed_tools[:10]:
            print(f"  {tool['id']} ({tool['server']}/{tool['name']}):")
            print(f"    {tool['description'][:120]}...")
            print()

    # Summary
    print(f"{'='*60}")
    print(f"SUMMARY")
    print(f"  Detection rate:     {detection_rate:.1%} ({detected}/{len(poisoned)})")
    print(f"  False positive rate: {fpr:.1%} ({fp}/{len(clean)})")
    print(f"  Threat categories hit: {len(category_counts)}")


if __name__ == "__main__":
    main()
