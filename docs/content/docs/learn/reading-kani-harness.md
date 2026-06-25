+++
title = "21. Reading a Kani Harness"
description = "A line-by-line walkthrough of a real navra proof: the capability attenuation harness that proves child tokens can never escalate privileges beyond their parent."
weight = 210
template = "docs/page.html"

[extra]
part = "verification"
toc = true
+++

## What you already know

You know what Kani does at a high level: it takes Rust code, converts it to boolean constraints, and uses a SAT solver to prove properties hold for all inputs within bounds. Now we read an actual proof to see what this looks like in practice.

## The property we want to prove

navra uses capability tokens for agent authentication. A parent agent can delegate a capability token to a child agent. The child token must never have more privileges than the parent. Specifically:

- The child's *ring* (privilege level, 0 = highest) must be the same as or higher (less privileged) than the parent's ring.
- The child's *expiry* must be the same as or earlier than the parent's expiry.

If either rule is violated, `check_attenuation` must reject the delegation. This is the attenuation property -- privileges can only shrink as tokens are delegated, never grow.

## The function under verification

Here is the core function (simplified from `navra-auth/src/auth/capability.rs`):

```rust
pub fn check_attenuation(
    parent_ring: u8,
    child_ring: u8,
    parent_exp: u64,
    child_exp: u64,
) -> Result<(), AttenuationError> {
    if child_ring < parent_ring {
        return Err(AttenuationError::RingEscalation);
    }
    if child_exp > parent_exp {
        return Err(AttenuationError::ExpiryExtension);
    }
    Ok(())
}
```

A child with ring 0 trying to delegate from a parent with ring 2 is escalation. A child with expiry in 2027 trying to delegate from a parent that expires in 2026 is extension. Both must be rejected.

## The Kani harness: ring escalation

```rust
#[kani::proof]
fn ring_escalation_rejected() {
    let parent_ring: u8 = kani::any();
    let child_ring: u8 = kani::any();
    kani::assume(parent_ring <= 3);
    kani::assume(child_ring <= 3);
    let result = check_attenuation(parent_ring, child_ring, 1000, 1000);
    if child_ring < parent_ring {
        assert!(result.is_err());
    }
}
```

Let's walk through each line.

**`#[kani::proof]`** marks this function as a Kani proof harness. When you run `cargo kani`, it will find this function and attempt to verify it.

**`let parent_ring: u8 = kani::any();`** declares a symbolic variable. This is not a random value -- it represents *all possible* `u8` values simultaneously. The solver will consider every value from 0 to 255.

**`kani::assume(parent_ring <= 3);`** constrains the symbolic variable. navra uses rings 0, 1, 2, and 3. Values above 3 are not valid rings, so we exclude them. This is not cheating -- it is specifying the domain. The proof covers all valid inputs.

**`let result = check_attenuation(parent_ring, child_ring, 1000, 1000);`** calls the function with symbolic rings and fixed expiry values. We fix the expiry at 1000 for both because this harness only tests the ring property. A separate harness tests expiry.

**`if child_ring < parent_ring { assert!(result.is_err()); }`** states the property: if the child's ring is more privileged (lower number) than the parent's ring, the function must return an error.

What happens when Kani runs this? The solver explores all 16 combinations of (parent_ring, child_ring) where both are in 0..3. For each combination where `child_ring < parent_ring`, it verifies that `check_attenuation` returns `Err`. If any combination produces `Ok` when it should have produced `Err`, the solver reports a counterexample.

## The complementary harness

The ring escalation harness proves that bad inputs are rejected. This companion harness proves that good inputs are accepted:

```rust
#[kani::proof]
fn valid_ring_accepted() {
    let parent_ring: u8 = kani::any();
    let child_ring: u8 = kani::any();
    kani::assume(parent_ring <= 3);
    kani::assume(child_ring <= 3);
    kani::assume(child_ring >= parent_ring);
    let result = check_attenuation(parent_ring, child_ring, 1000, 1000);
    assert!(result.is_ok());
}
```

The additional `assume` constrains the search to valid delegations (child ring >= parent ring). The assertion says the function must accept these. Together, the two harnesses prove that `check_attenuation` correctly partitions the input space: escalations are rejected, valid delegations are accepted, and there are no edge cases where a valid delegation is incorrectly rejected or an escalation slips through.

## The transitivity harness

This is the most interesting proof. It verifies that attenuation is transitive:

```rust
#[kani::proof]
fn transitive_attenuation() {
    let r0: u8 = kani::any();
    let r1: u8 = kani::any();
    let r2: u8 = kani::any();
    kani::assume(r0 <= 3 && r1 <= 3 && r2 <= 3);
    let e0: u64 = kani::any();
    let e1: u64 = kani::any();
    let e2: u64 = kani::any();
    kani::assume(e0 <= 1000 && e1 <= 1000 && e2 <= 1000);

    let parent_to_child = check_attenuation(r0, r1, e0, e1);
    let child_to_grandchild = check_attenuation(r1, r2, e1, e2);

    if parent_to_child.is_ok() && child_to_grandchild.is_ok() {
        assert!(check_attenuation(r0, r2, e0, e2).is_ok());
    }
}
```

This harness declares three levels of delegation: parent, child, grandchild. It checks: if parent can delegate to child, and child can delegate to grandchild, then parent can delegate directly to grandchild. This is important because delegation chains must be safe. If A delegates to B and B delegates to C, it must be impossible for C to have more privileges than A -- even indirectly.

The solver explores all valid combinations of three rings (4^3 = 64) and three expiry values (bounded to 0..1000). For every combination where the first two delegations are valid, it verifies that the transitive delegation is also valid.

Why does this matter? Suppose `check_attenuation` had a subtle bug where `ring == 2` was accepted as a valid delegation from `ring == 3`, but `ring == 0` was correctly rejected from `ring == 3`. The first delegation (3 to 2) would pass. The second delegation (2 to 0) might pass due to a different bug. But the transitive check (3 to 0) would fail. The transitivity proof catches bugs that the pairwise proofs miss.

## Reading the output

When Kani verifies successfully, the output looks like:

```
Checking harness ring_escalation_rejected...
 - Status: SUCCESS
 - Description: "assertion at line 8"

Checking harness valid_ring_accepted...
 - Status: SUCCESS
 - Description: "assertion at line 8"

Verification successful for all harnesses.
```

When verification fails, Kani provides a concrete counterexample:

```
Checking harness ring_escalation_rejected...
 - Status: FAILURE
 - Description: "assertion at line 8"
 - Counterexample:
   parent_ring = 2
   child_ring = 1
   result = Ok(())
```

This tells you exactly which input violates the property. You can reproduce it as a unit test, fix the bug, and re-verify.

## The pattern

Most Kani harnesses in navra follow the same pattern:

1. Declare symbolic inputs with `kani::any()`.
2. Constrain them to the valid domain with `kani::assume()`.
3. Call the function under verification.
4. Assert the property that must hold.

The harnesses are typically 5-15 lines of code. They live alongside unit tests in `#[cfg(kani)] mod kani_proofs` blocks at the bottom of each file.

## What's next

Kani proves properties about individual functions. But what about properties that span multiple function calls over time -- like "a session's taint level never decreases" or "two sessions never interfere"? That's where TLA+ comes in, and that's the next chapter.
