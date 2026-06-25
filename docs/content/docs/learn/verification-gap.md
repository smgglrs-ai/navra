+++
title = "24. The Verification Gap"
description = "What navra does NOT prove. No end-to-end proof like seL4. The semantic taint gap. Covert channels. Key management. Being honest about limits builds trust."
weight = 240
template = "docs/page.html"

[extra]
part = "verification"
toc = true
+++

## What you already know

You have seen navra's three-layer verification pyramid: 154 Kani proofs for per-function correctness, 6 TLA+ specifications for protocol behavior, and 2,500+ tests covering integration and adversarial scenarios. That sounds like a lot. This chapter is about what it does not cover.

## No end-to-end proof

seL4 is a microkernel with a complete formal proof: the specification, the implementation, and the compiled binary are all proven to match. If the hardware works correctly, seL4 does exactly what its specification says, for all inputs, in all states, under all interleavings.

navra does not have this. navra's proofs are *per-component*: individual functions are proven correct, protocol invariants are verified against a model, and the rest is tested. The gap between "each component is correct" and "the assembled system is correct" is not formally bridged.

What could hide in this gap? A wiring bug: component A is correct, component B is correct, but A calls B with the wrong argument order. A missing check: the ACL engine correctly evaluates allow/deny, but a new code path in the handler skips the ACL engine entirely. A race condition: the taint check reads a label, another thread updates it, and the write check uses a stale value.

navra mitigates these gaps with integration tests and code review, but mitigation is not proof. The honest statement is: navra's individual security primitives are formally verified. The system as a whole is tested but not proven.

## The semantic taint gap

This is navra's most fundamental limitation. IFC (Information Flow Control) tracks *labels*, not *meaning*.

Consider this scenario: an agent reads a file containing customer names. The file's label is `Confidential`. The agent's taint is raised to `Confidential`. navra now blocks the agent from writing to public destinations. So far, so good.

But suppose the agent does not copy the names directly. Instead, it summarizes: "The file contains 47 customer records from the Northeast region." This summary does not contain any individual name. The PII filter finds no SSNs, no email addresses, no phone numbers. But the summary was *derived from* confidential data. The IFC label says the agent is tainted, so the write is blocked.

Now the opposite problem: the agent reads a public file, but the file happens to mention "John Smith, 555-0123, john@example.com" as example data in a test fixture. The PII filter flags it. The IFC label says the content is public. The label is correct (it is public test data) but the content filter fires anyway.

IFC tracks the *provenance* of data (where it came from) but not the *semantics* (what it means). A label cannot tell you whether "47 customer records from the Northeast" is a privacy risk or not. That requires understanding the content, the context, and the downstream use -- which is a problem for privacy engineers, not for automated systems.

navra's PrivacyRouter adds heuristic detection (regex, NER, ML models) on top of IFC labels. This catches many real privacy leaks. But no automated system can fully determine whether a piece of text derived from confidential data is itself confidential. This is an open research problem, not a shipping feature.

## The async gap

navra's `handle_call_tool` function is async. Kani cannot verify async code. The workaround is to extract pure logic into synchronous functions and verify those:

```rust
// This is verified by Kani:
pub fn check_attenuation(parent_ring: u8, child_ring: u8, ...) -> Result<(), Error>

// This calls the verified function but is not itself verified:
pub async fn handle_call_tool(&self, params: CallToolParams, ctx: CallContext) -> CallToolResult {
    // ... calls check_attenuation, check_acl, etc.
}
```

The async handler orchestrates verified building blocks. Each building block is proven correct. But the orchestration itself -- the order of checks, the error handling between checks, the async state machine -- is tested, not proven.

This is a real gap. If someone adds a new code path in `handle_call_tool` that bypasses the ACL check under certain conditions, no Kani proof will catch it. Integration tests should catch it if the test covers that code path. But "should" is weaker than "will."

navra's chokepoint design mitigates this: by concentrating all enforcement in one function rather than distributing it across handlers, there are fewer places where a check can be skipped. But the mitigation is architectural, not formal.

## Covert channels

A covert channel is a way to communicate information that bypasses the enforcement mechanism. IFC tracks data flow through explicit channels (function arguments, return values, variable stores). It does not track:

**Timing channels.** An agent can encode information in how long it takes to respond. If it takes 1 second, the bit is 0. If it takes 2 seconds, the bit is 1. navra cannot detect this without adding noise to all timing, which degrades performance.

**Resource channels.** An agent can encode information in resource consumption: allocate a specific amount of memory, or generate a specific number of errors. navra records these events in the blackbox, but does not interpret them as communication channels.

**Side-effect channels.** An agent with access to a tool that creates files could encode information in the filenames. The content might be empty and pass all filters, but the filename `customer_count_47.txt` leaks the information.

Covert channels are a known limitation of all IFC systems, not just navra's. They are theoretically impossible to eliminate completely in a system where agents share resources. The practical mitigation is to reduce the bandwidth of covert channels (rate limiting, noise injection) and to monitor for anomalous patterns (the blackbox helps here). But a determined attacker with enough patience can always leak information through side channels.

## Key management

navra uses HMAC-SHA256 for signing capability tokens. The signing key is loaded from a file (`~/.config/navra/signing.key`) or generated on first run. This is adequate for a single-machine deployment, but it has limitations:

- **Key rotation.** There is no automated key rotation. If the signing key is compromised, all tokens signed with it must be revoked. navra supports revocation lists, but the operational process of rotating keys and reissuing tokens is manual.
- **Key storage.** The key is stored as a file on disk, protected by filesystem permissions. This is the same security model as SSH keys. It is not hardware-backed (no TPM, no HSM, no secure enclave). A process with root access can read the key.
- **Key distribution.** In a multi-machine deployment, the signing key must be shared between machines. navra does not provide a key distribution mechanism. The operator must copy the key file, use a secrets manager, or configure each machine independently.

Peter Gutmann has written extensively about the gap between cryptographic theory and key management practice. The algorithms are provably secure; the key handling is usually the weakest link. navra is no exception.

## Model limitations

navra uses ONNX models for named entity recognition and privacy classification. These models have their own failure modes:

- **False negatives.** The NER model might miss a name it hasn't seen during training. "Elon Musk" is easy; "Khadija bint Khuwaylid" might be missed depending on training data representation.
- **False positives.** The model might classify "Rue de Rivoli" as a person's name in certain contexts. The privacy model might flag technical terms that happen to overlap with PII patterns.
- **Adversarial inputs.** ML models are vulnerable to adversarial perturbation. An attacker who knows the model architecture might craft inputs that bypass detection: "J.o.h.n S.m.i.t.h" instead of "John Smith."

navra mitigates these by running multiple detectors (regex, NER, ML model, custom patterns) and using a deny-wins threshold. But the models are heuristic, not formal. Their accuracy is measured in percentages, not proofs.

## The specification gap

TLA+ specifications are verified by the TLC model checker, but the specifications are written by humans. If the TLA+ spec does not accurately model the Rust implementation, TLC can happily verify properties of a system that does not exist.

Consider the SessionIsolation specification. It models `labels` as a function from session IDs to integers, and `Absorb` as an operation that takes the maximum. If the Rust implementation uses a different join operation -- say, bitwise OR instead of max -- the TLA+ proof is irrelevant. The model checker verifies the spec, not the code.

navra mitigates this with the proof map (`formal/PROOF_MAP.md`), which explicitly links each TLA+ invariant to the Rust function it models. The IFC lattice join operation is verified by both TLA+ (protocol-level behavior) and Kani (the actual Rust function). If the two diverge, at least one will fail.

But the proof map is maintained by hand. It can become stale. A rename that changes `join` to `merge` could break the correspondence without either verification system noticing. This is a process gap, not a tool gap -- it requires discipline, not technology.

## The completeness gap

navra's 154 Kani proofs cover security-critical pure functions. They do not cover all functions. Large parts of the codebase -- HTTP routing, configuration parsing, transport negotiation, module loading -- have tests but no proofs.

The decision about what to prove is a risk assessment. Functions that enforce security boundaries (ACLs, IFC, capability delegation) get proofs. Functions that format log messages or parse TOML do not. This is reasonable, but it means a bug in the configuration parser could misconfigure a security boundary in a way that no proof catches.

The testing pyramid exists to cover these gaps: integration tests verify that configuration feeds into the security pipeline correctly, and adversarial evaluations test the assembled system. But the coverage is probabilistic (test quality) rather than certain (proof quality).

## What we do about it

Honesty about limitations is not the same as resignation. navra takes specific actions to address each gap:

- **The assembly gap** is addressed by integration tests, adversarial evaluations, and the chokepoint pattern (one function, fewer wiring opportunities).
- **The semantic gap** is addressed by the PrivacyRouter's multi-detector strategy and configurable thresholds. Operators who handle sensitive data can raise the threshold; operators who need usability can lower it.
- **Covert channels** are mitigated by rate limiting and blackbox recording. The blackbox makes anomalous patterns detectable after the fact, even if they cannot be prevented in real time.
- **Key management** is documented as an operational responsibility. navra provides the cryptographic primitives; the operator provides the key management process.
- **Model accuracy** is addressed by running multiple independent detectors. A name that passes the regex filter might be caught by the NER model. A pattern that passes the NER model might be caught by the custom patterns.
- **The async gap** is addressed by extracting pure logic into synchronous functions that Kani can verify. The chokepoint pattern minimizes the amount of unverified orchestration code.
- **The specification gap** is addressed by the proof map, which cross-references TLA+ invariants with Kani harnesses. When both verification systems prove properties of the same function, the spec-to-implementation correspondence is strengthened.
- **The completeness gap** is addressed pragmatically: functions that enforce security boundaries get proofs, and the rest get thorough testing. New security-critical code should include Kani harnesses as part of the review checklist.

## The industry context

It is worth putting navra's verification gap in perspective. Most agent frameworks have no formal verification at all. No Kani proofs, no TLA+ specs, no proof map. The security model is "trust the developer" and the audit trail is "check the logs, if they exist."

navra's gap is real, but it is a documented gap in a system that has 154 proofs, 6 TLA+ specs, 2,500+ tests, and explicit mapping between formal properties and implementations. The alternative is not a better-verified system -- it is an unverified one.

The honest comparison is not "navra vs. seL4" (navra loses). It is "navra vs. running agents with no gateway" (navra wins by a wide margin). The verification gap tells you where to focus future work, not where to abandon the approach.

Transparency about limitations serves two purposes. First, it helps operators make informed deployment decisions. They know what navra protects against and what it does not. Second, it focuses development effort. The verification gap is a roadmap: close the async gap by extracting more pure logic; close the semantic gap by improving the PrivacyRouter; close the covert channel gap by adding anomaly detection on blackbox patterns.

Every security system has a verification gap. The question is whether the gap is known or unknown, documented or hidden. navra chooses documentation over marketing, and that choice -- being honest about what the system cannot do -- is itself a security property.

## What's next

We now shift from verification to privacy. In Part VI, we look at how navra detects PII in tool call content -- starting with the fastest detector: regex patterns.
