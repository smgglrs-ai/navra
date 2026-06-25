+++
title = "23. Property Testing and the Testing Pyramid"
description = "Where formal proofs end, tests begin. navra combines 154 Kani proofs, 6 TLA+ specs, and 2,500+ tests into a verification pyramid. Each layer covers what the others cannot."
weight = 230
template = "docs/page.html"

[extra]
part = "verification"
toc = true
+++

## What you already know

You know that Kani proves per-function properties and TLA+ proves protocol-level properties. Both are powerful, but both have limits: Kani cannot verify async code, TLA+ cannot verify the actual implementation. This chapter covers the third layer of verification: tests.

## The testing pyramid

navra's verification strategy is a pyramid with three layers:

```
          /\
         /  \     154 Kani proofs
        /    \    (per-function, exhaustive)
       /------\
      /        \   6 TLA+ specifications
     /          \  (protocol-level, state exploration)
    /------------\
   /              \  2,500+ tests
  /                \ (unit, integration, e2e, adversarial)
 /------------------\
```

Each layer trades off coverage scope against implementation fidelity:

- **Kani proofs** cover the least code but with the strongest guarantees. They verify actual Rust functions for all possible inputs. They cannot test async behavior, I/O, or cross-crate interactions.
- **TLA+ specs** cover protocol-level behavior but verify a model, not the implementation. They catch design bugs (incorrect state machines, missing transitions) but cannot catch implementation bugs (off-by-one errors, wrong variable names).
- **Tests** cover the most code with the weakest guarantees. They verify specific scenarios, including async code, I/O, cross-crate interactions, and end-to-end behavior. But they only cover the inputs you think to test.

The layers are complementary. A bug that passes Kani verification might be caught by TLA+ (wrong protocol design). A bug that passes TLA+ might be caught by Kani (wrong implementation of a verified design). A bug that passes both might be caught by tests (interaction between two components that were verified in isolation).

## Unit tests: the foundation

navra's unit tests live in `#[cfg(test)] mod tests` blocks at the bottom of each file. They follow standard Rust conventions:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_always_wins() {
        let rules = ToolRules::new(vec![
            ToolRule::allow("file_*"),
            ToolRule::deny("file_write"),
        ]);
        assert_eq!(rules.check("file_write"), ToolPolicy::Deny);
        assert_eq!(rules.check("file_read"), ToolPolicy::Allow);
    }
}
```

Unit tests verify that individual functions behave correctly for specific inputs. They are fast (thousands per second), easy to write, and easy to debug. Their weakness is that they only test the cases the developer thought of.

navra uses unit tests extensively for:

- **Serialization roundtrips**: JSON-RPC types serialize and deserialize correctly.
- **Validation logic**: Invalid inputs are rejected with the right error.
- **Filter matching**: PII patterns match what they should and don't match what they shouldn't.
- **ACL evaluation**: Permission rules produce the expected allow/deny decisions.

## Property-based testing: randomized exploration

Property-based testing (using crates like `proptest` or `quickcheck`) bridges the gap between unit tests and Kani proofs. Instead of testing specific inputs, you describe a property that should hold for *any* valid input, and the framework generates random inputs to test it:

```rust
#[test]
fn label_join_is_commutative() {
    // For any two labels, join(a, b) == join(b, a)
    for a in all_labels() {
        for b in all_labels() {
            assert_eq!(a.join(b), b.join(a));
        }
    }
}
```

Property tests generate hundreds or thousands of random inputs per run. They are good at finding edge cases that developers miss -- unusual unicode characters, empty strings, boundary values. They are weaker than Kani proofs (random sampling vs. exhaustive search) but stronger than hand-written unit tests (hundreds of inputs vs. a handful).

navra uses property-style testing for:

- **Content filter accuracy**: Generate random strings containing PII patterns mixed with legitimate text, verify detection rates.
- **Pagination correctness**: Generate random list sizes and page sizes, verify that iterating through all pages produces the complete list.
- **Configuration parsing**: Generate TOML configurations with various combinations of optional fields, verify parsing succeeds or fails appropriately.

## Integration tests: cross-crate behavior

Integration tests live in `tests/` directories within each crate. They test interactions between components:

```rust
#[tokio::test]
async fn tainted_write_denied() {
    let server = test_server_with_ifc();
    let ctx = test_ctx_with_taint(Integrity::Untrusted);
    let result = server.handle_call_tool(
        CallToolParams { name: "file_write".into(), arguments: json!({"path": "/tmp/out"}) },
        ctx,
    ).await;
    assert!(result.is_error);
    assert!(result.content[0].as_text().contains("Permission denied"));
}
```

Integration tests verify that the wiring between components is correct -- that the ACL check in handlers.rs actually calls the ACL engine, that the IFC check actually reads the session's taint level, that content filters actually run on tool results.

These tests catch bugs that unit tests miss: a function works correctly in isolation but is called with the wrong arguments, or two correct functions interact incorrectly because they make incompatible assumptions.

## End-to-end tests: the real server

E2e tests spawn an actual navra server process and interact with it over MCP. They test the full stack: transport layer, authentication, session management, tool execution, content filtering, and blackbox recording:

```rust
#[tokio::test]
async fn e2e_session_lifecycle() {
    let server = spawn_navra_server().await;
    let client = McpClient::connect(&server.url).await;

    // Initialize
    let init = client.initialize().await;
    assert_eq!(init.protocol_version, "2025-03-26");

    // List tools
    let tools = client.list_tools().await;
    assert!(!tools.is_empty());

    // Call a tool
    let result = client.call_tool("echo", json!({"text": "hello"})).await;
    assert!(!result.is_error);
}
```

E2e tests are slow (they start a server process) and fragile (they depend on system state), but they test the one thing no other verification layer can test: does the whole system work when assembled?

navra's e2e tests include adversarial scenarios: sending malformed JSON-RPC, exceeding rate limits, attempting privilege escalation, injecting prompt injection patterns into tool responses. These tests must run serialized (not in parallel) because they can OOM when spawning multiple server processes.

## Adversarial evaluation

Beyond standard e2e tests, navra has adversarial evaluation suites that test the security pipeline against known attack patterns:

- **Prompt injection**: Tool responses containing `<system>` tags, imperative overrides, and other injection patterns are detected and blocked.
- **PII exfiltration**: Tool results containing SSNs, credit card numbers, and email addresses are caught by content filters.
- **Privilege escalation**: Agents with restricted permissions cannot call tools outside their allowed set, even with creative tool name variations.
- **IFC bypass**: Tainted agents cannot write to trusted destinations through any combination of variable references and tool chains.

These are the tests that validate navra's security claims against real-world attack patterns.

## The coverage philosophy

navra does not chase a coverage percentage. Instead, it uses the verification pyramid to allocate effort:

1. **Prove** what you can prove. Security-critical pure functions get Kani proofs. Protocol-level invariants get TLA+ specs.
2. **Test** what you can't prove. Async handlers, I/O interactions, and cross-crate wiring get integration tests.
3. **Evaluate** what you can't test. Adversarial scenarios that depend on realistic attack patterns get evaluation suites.

Every verification technique has blind spots. The goal is to arrange the techniques so each one covers the others' blind spots. Kani catches implementation bugs in pure functions. TLA+ catches protocol design bugs. Integration tests catch wiring bugs. Adversarial evaluations catch security gaps.

## What's next

Honest verification means being explicit about what is NOT verified. The next chapter covers the verification gap -- the properties navra does not prove, the attacks it cannot prevent, and why transparency about limitations builds more trust than overclaiming.
