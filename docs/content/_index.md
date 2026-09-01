+++
title = "navra"

[extra]
lead = "Secure agentic AI framework for Rust. MCP gateway, agent SDK, multi-agent flow engine, and model server — unified behind capability-based security, information flow control, and a 22-hook safety pipeline."
url = "docs/getting-started"
repo_url = "https://github.com/smgglrs-ai/navra"
repo_license = "Apache-2.0 · Rust · 25 crates · ~172K LoC"

[[extra.list]]
title = "Security Gateway"
content = "Every tool call passes through a 9-gate enforcement pipeline: auth, rate limiting, capability tokens, tool policies, domain rules, path ACLs, IFC taint tracking, and content safety. 168 Kani proofs verify the invariants."

[[extra.list]]
title = "Agent SDK"
content = "Build agents in Rust with a fluent builder API. ReAct tool-use loop, 6 model backends (Ollama, Anthropic, OpenAI-compat, OGX, ONNX, CLI), signals, hibernation, and deterministic replay."

[[extra.list]]
title = "Multi-Agent Flows"
content = "Orchestrate agent teams with DAG execution, handoff routing, and iterative analysis. Mesh communication (mailbox + blackboard) with IFC enforcement. Back-edges, cross-validation, checkpoint/recovery."

[[extra.list]]
title = "Content Safety"
content = "8 safety profiles with regex, NER, and ML classifiers. PII detection (US + EU + multilingual), SSRF blocking, exfiltration detection, prompt injection defense, credential brokering, and canary tokens."

[[extra.list]]
title = "Model Serving"
content = "Embedded llama.cpp with LRU hot-swap, GPU auto-detection (NVIDIA/AMD/Intel), KV cache quantization, speculative decoding. 4 isolation modes: in-process, direct, Podman, OpenShell. Model hub with ollama://, hf://, oci:// URIs."

[[extra.list]]
title = "Cognitive Personas"
content = "Persona factory with YAML-based identity artifacts: mandates, heuristics, directives, specializations, skill cards. Per-phase model routing, context budget management, upstream auto-discovery. SHA-256 integrity verification."

[[extra.list]]
title = "Memory & RAG"
content = "Working memory with forking, knowledge store with FTS5, entity graphs, and distillation pipeline. Hybrid FTS5 + vector RAG with cross-encoder reranking, agentic retrieval, and semantic query caching."

[[extra.list]]
title = "Always-On Audit"
content = "SHA-256 hash-chained blackbox captures every tool call — no opt-in required. Tamper-detectable, GDPR-aware (PII sanitization, right to erasure), compliance-mapped to EU AI Act, SOC2, and ISO 42001."
+++
