+++
title = "Learn"
description = "From zero to understanding how a security gateway protects AI agents — threats, OS primitives, cryptography, protocols, and verification."
sort_by = "weight"
weight = 50
template = "docs/section.html"

[extra]
toc = true
no_card_list = true

[[extra.sidebar_parts]]
title = "Part I: The Threat"
id = "threat"

[[extra.sidebar_parts]]
title = "Part II: OS Security"
id = "os-security"

[[extra.sidebar_parts]]
title = "Part III: Cryptographic Identity"
id = "crypto"

[[extra.sidebar_parts]]
title = "Part IV: The Protocol"
id = "protocol"

[[extra.sidebar_parts]]
title = "Part V: Verification"
id = "verification"

[[extra.sidebar_parts]]
title = "Part VI: Privacy Engineering"
id = "privacy"
+++

You don't need a security background. You don't need to know what a capability token is. You do need to understand what AI agents are — that they call tools, read files, and make decisions. Everything beyond that, we build from scratch.

This section takes you from "I use AI tools but I don't know how they're secured" all the way to understanding how an MCP gateway enforces least privilege, information flow control, and cryptographic identity for AI agent teams.

## Part I: The Threat Model

| # | Topic | What you'll understand |
|---|-------|----------------------|
| 0 | [What Agents Actually Do](what-agents-do/) | Tool calls, not just chat — why agents are processes, not users |
| 1 | [Why Prompts Aren't Security](prompts-arent-security/) | System prompts as access control — and why they fail |
| 2 | [Prompt Injection](prompt-injection/) | The fundamental unsolvable problem in AI security |
| 3 | [The Multi-Agent Surface](multi-agent-surface/) | How delegation, shared context, and tool chains multiply risk |
| 4 | [What a Gateway Can and Cannot Do](gateway-limits/) | Infrastructure-level enforcement vs semantic-level attacks |

## Part II: OS Security Primitives

| # | Topic | What you'll understand |
|---|-------|----------------------|
| 5 | [Agents as Processes](agents-as-processes/) | Why the OS analogy works — isolation, scheduling, identity |
| 6 | [Capabilities](capabilities/) | Dennis & Van Horn to Capsicum — unforgeable tokens for access control |
| 7 | [Privilege Rings](privilege-rings/) | Ring 0/1/2, deny-wins, why outer rings can't escalate |
| 8 | [Information Flow Control](information-flow-control/) | Bell-LaPadula, lattices, taint labels — preventing data exfiltration |
| 9 | [The Microkernel Idea](the-microkernel/) | Mach → L4 → seL4 — small trusted base, everything else is userland |

## Part III: Cryptographic Identity

| # | Topic | What you'll understand |
|---|-------|----------------------|
| 10 | [Digital Signatures](digital-signatures/) | Ed25519 — how signing works and why agents need it |
| 11 | [Decentralized Identifiers](decentralized-identifiers/) | DIDs and did:key — identity without a registry |
| 12 | [Capability Tokens](capability-tokens/) | CBOR encoding, attenuation, expiry — why not JWT |
| 13 | [Delegation Chains](delegation-chains/) | How a leader issues narrower tokens to specialists |
| 14 | [Post-Quantum Readiness](post-quantum/) | ML-DSA, hybrid signatures, algorithm agility |

## Part IV: The MCP Protocol

| # | Topic | What you'll understand |
|---|-------|----------------------|
| 15 | [JSON-RPC and Transports](json-rpc/) | The wire format — JSON-RPC 2.0 over HTTP, stdio, WebSocket |
| 16 | [Tools, Resources, Prompts](tools-resources-prompts/) | The three MCP primitives and what flows through each |
| 17 | [The Security Chokepoint](the-chokepoint/) | Where enforcement happens — handle_call_tool as the system call boundary |
| 18 | [Upstream and Proxy](upstream-and-proxy/) | How the gateway mediates access to external MCP servers |
| 19 | [Agent-to-Agent Protocol](a2a-protocol/) | A2A for inter-agent communication — agent cards, task lifecycle |

## Part V: Formal Verification

| # | Topic | What you'll understand |
|---|-------|----------------------|
| 20 | [What Kani Proves](what-kani-proves/) | Bounded model checking, SAT solvers, "all inputs within bounds" |
| 21 | [Reading a Kani Harness](reading-kani-harness/) | Annotated walkthrough of a real proof from navra |
| 22 | [TLA+ Specifications](tla-specifications/) | Protocol-level model checking — what temporal logic adds |
| 23 | [Property Testing](property-testing/) | Where proofs end and tests begin — complementary approaches |
| 24 | [The Verification Gap](verification-gap/) | What remains unproven and why |

## Part VI: Privacy Engineering

| # | Topic | What you'll understand |
|---|-------|----------------------|
| 25 | [PII Detection with Regex](pii-regex/) | Fast pattern matching — SSNs, credit cards, emails |
| 26 | [Named Entity Recognition](named-entity-recognition/) | ONNX models for detecting names, addresses, organizations |
| 27 | [The Privacy Router](the-privacy-router/) | Routing, short-circuit, language detection — coordinating 5 detectors |
| 28 | [False Positives and Thresholds](false-positives/) | The tradeoff between safety and usability |
| 29 | [Compliance Mapping](compliance-mapping/) | EU AI Act, SOC2, ISO 42001 — what the blackbox addresses |

## How to read this

**Part I** stands alone — stop after Chapter 4 and you'll understand why navra exists and what problem it solves.

**Part II** explains the classical OS security concepts that navra adapts — capabilities, rings, IFC, microkernels. If you're a security person, skim this. If you're an AI person, read it carefully.

**Part III** covers the cryptography behind agent identity and capability tokens — Ed25519, DIDs, CBOR, delegation chains.

**Part IV** explains the MCP protocol and where security enforcement happens in the request lifecycle.

**Part V** covers formal verification — what Kani and TLA+ prove about navra's security properties, and what they don't.

**Part VI** covers privacy engineering — how content filtering works at the gateway layer, from regex to ONNX models.

**Go in order** within each part. After Part I, the other parts can be read in any order based on interest.
