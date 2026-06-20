+++
title = "navra"

[extra]
lead = "Secure MCP gateway daemon for Linux desktops. Microkernel architecture with capability-based security, information flow control, and cognitive personas for AI agent teams."
url = "docs/getting-started"
repo_url = "https://github.com/smgglrs-ai/navra"
repo_license = "Apache-2.0 · Rust · 22 crates · ~150K LoC"

[[extra.list]]
title = "Capability-Based Security"
content = "Ed25519-signed capability tokens with delegation chains. Agents receive attenuated permissions — never more than their parent. Verified by 146 Kani proofs."

[[extra.list]]
title = "Information Flow Control"
content = "Gateway-enforced IFC with a 2×4 product lattice. Taint labels propagate through tool chains. Deny-wins ACLs prevent data exfiltration at the infrastructure layer."

[[extra.list]]
title = "Microkernel Separation"
content = "22-crate Rust workspace. Security kernel enforces access control at a single chokepoint. Tool modules run in-process or as standalone MCP servers for crash isolation."

[[extra.list]]
title = "Cognitive Personas"
content = "43 structured YAML personas across 7 domains. Genotype/phenotype separation — version-controlled identity artifacts compiled into runtime prompts by the Weaver."

[[extra.list]]
title = "Always-On Audit"
content = "Hash-chained blackbox recorder captures every tool call at the gateway layer. No opt-in, no agent cooperation required. Tamper-detectable, compliance-ready."

[[extra.list]]
title = "Fully Local Execution"
content = "Runs on consumer hardware with Ollama. Composite model cards enable lead agents to select teammates based on task requirements, cost, and data sensitivity."
+++
