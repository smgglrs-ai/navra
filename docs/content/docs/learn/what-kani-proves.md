+++
title = "20. What Kani Proves"
description = "Bounded model checking with Kani does not test your code — it proves properties hold for all inputs within bounds. navra has 154 proofs. This chapter explains what that means and why it matters."
weight = 200
template = "docs/page.html"

[extra]
part = "verification"
toc = true
+++

## What you already know

You have seen navra's security pipeline: ACLs, IFC labels, content filtering, blackbox recording. You know what the code *does*. But how do you know it does it *correctly*? Tests check specific inputs. Code review catches bugs a human notices. Neither can check every possible input. That's where Kani comes in.

## Testing vs. proving

A test says: "For this specific input, the output is correct."

A proof says: "For ALL inputs within these bounds, this property holds."

When you write a unit test for a function that adds two numbers, you might check that `add(2, 3) == 5` and `add(0, 0) == 0` and `add(-1, 1) == 0`. You've tested three inputs. The function might still be wrong for `add(i64::MAX, 1)`.

When you write a Kani proof for the same function, you declare: "let `a` be any `i64`, let `b` be any `i64`, assert that `add(a, b)` does not overflow." Kani then checks this assertion against *every possible pair* of `i64` values. Not by running them all -- that would take longer than the age of the universe -- but by translating the code into a mathematical model and using a SAT solver to search for counterexamples.

If the solver finds an input that violates the assertion, Kani reports it with a concrete counterexample. If the solver exhausts the search space without finding a violation, Kani reports that the property is verified.

## How Kani works

Kani is a model checker for Rust, developed at Amazon Web Services. It works by compiling your Rust code into a mathematical representation (specifically, a set of boolean constraints) and feeding it to a SAT/SMT solver. The solver either finds an assignment of variables that violates your assertion (a counterexample) or proves that no such assignment exists.

The key concepts:

**Symbolic variables.** Instead of concrete values, you declare *symbolic* variables using `kani::any()`. A symbolic `u8` represents all 256 possible values simultaneously. The solver explores all of them.

**Assumptions.** `kani::assume(x < 10)` restricts the symbolic variable to values where `x < 10`. This is not a test precondition -- it constrains the search space. The solver only considers inputs that satisfy all assumptions.

**Assertions.** `assert!(result.is_ok())` states a property that must hold for all valid inputs. If the solver finds any input where the assertion fails (and all assumptions hold), verification fails.

**Bounded checking.** The "bounded" part means Kani unrolls loops up to a fixed depth and handles recursion up to a fixed depth. It cannot reason about unbounded iteration, which is why you set bounds on your symbolic variables.

## Why Rust specifically

Kani works with Rust because Rust's type system and ownership model give the solver more structure to work with. A Rust function that takes `&[u8]` cannot receive a null pointer -- the type system prevents it. A Rust function that returns `Result<T, E>` must handle both cases -- the compiler enforces it. These guarantees reduce the search space the solver needs to explore.

Other languages have model checkers (CBMC for C, JPF for Java, TLA+ for specifications), but Rust's safety guarantees mean Kani starts from a higher baseline. It does not need to check for null pointer dereferences, use-after-free, or data races -- the compiler already prevents those. Kani focuses on *logical* correctness: does the function compute the right answer?

This is why navra is written in Rust rather than Go, Python, or TypeScript. The language's safety guarantees compound with formal verification to produce stronger assurance than either one alone.

## navra's 154 proofs

navra uses Kani proofs for security-critical code. Here are the categories:

**IFC lattice properties (12 proofs).** The information flow control system relies on a mathematical lattice. navra proves that the `join` operation is commutative, associative, idempotent, and monotonic. It proves that `can_write_to` and `can_read_from` satisfy the Bell-LaPadula no-write-down and no-read-up properties. These are not correctness tests -- they are proofs that the lattice axioms hold for every possible label combination.

**Taint propagation (5 proofs).** Taint can only increase, never decrease. navra proves this for individual absorb operations and for sequences of three consecutive absorbs. It also proves that `pii_implies_sensitive` -- if data is labeled as PII, it is always also labeled as sensitive.

**Capability delegation (7 proofs).** When a parent token delegates to a child token, the child must have equal or fewer privileges. navra proves that ring escalation is rejected, expiry extension is rejected, and attenuation is transitive: if A can delegate to B, and B can delegate to C, then A can delegate to C directly.

**Deny-wins ACL (4 proofs).** The ACL evaluation function uses a deny-wins rule: if any rule denies access, the request is denied regardless of allow rules. navra proves this exhaustively for all combinations of allow and deny flags.

**Pagination (3 proofs).** The cursor-based pagination logic is proven to produce correct page sizes, handle offset-past-end correctly, and roundtrip cursors without data loss.

**Content filtering, validation, and other properties** make up the remaining proofs, covering areas like UTF-8 boundary handling in content compression, configuration validation, and data structure invariants.

**Sandbox profile attenuation (4 proofs).** When a capability token specifies a sandbox profile, the child token's sandbox must be equal to or more restrictive than the parent's. Proofs verify that filesystem restrictions cannot be relaxed, network access cannot be widened, and process limits cannot be raised through delegation.

**Token validation (3 proofs).** Token expiry comparisons, ring level comparisons, and tool glob matching are verified for correctness across their input domains. These proofs catch subtle edge cases like equality handling (does `ring == ring` count as escalation?) and empty glob patterns.

## What "exhaustive" means

When the proof map says "Exhaustive (8^2)," it means the solver checked all 64 combinations. For `u8` variables bounded to 0..7 (navra's IFC label space has 8 possible values), "all inputs" literally means all inputs. There is no sampling, no heuristic, no probabilistic guarantee. The solver has either found a counterexample or proved none exists.

For larger types, Kani uses bounded verification. If you have two symbolic `u64` values, the solver cannot enumerate 2^128 combinations. Instead, you constrain them: `kani::assume(x <= 1000)`. The proof then covers all values within those bounds. This is weaker than proving the property for all `u64` values, but for security properties that depend on small enumerations (rings 0-3, labels 0-7, a handful of flags), the bounds cover the entire domain.

## The SAT solver underneath

You don't need to understand SAT solving to use Kani, but it helps to know what's happening. Kani compiles your Rust code (via MIR, the compiler's intermediate representation) into a set of boolean constraints. The assertion becomes a constraint that must be satisfiable -- specifically, Kani asks the solver: "Is there an input where the assertion is *false*?"

If the solver says "yes" (SAT), verification fails and you get a counterexample. If the solver says "no" (UNSAT), verification passes -- there is no input that violates the assertion.

Modern SAT solvers are remarkably efficient for structured problems. A Kani proof that covers millions of input combinations typically completes in seconds. The complexity depends on the code's structure, not the number of inputs.

## A concrete example

Before we dive into a full harness walkthrough (next chapter), here is the simplest Kani proof in navra. It verifies that cursor-based pagination roundtrips correctly:

```rust
#[kani::proof]
fn cursor_roundtrip() {
    let offset: u8 = kani::any();
    let encoded = encode_cursor(offset as usize);
    let req = PaginatedRequest {
        cursor: Some(encoded),
    };
    let decoded = req.decode_offset().unwrap();
    assert_eq!(decoded, offset as usize);
}
```

Five lines of meaningful code. The symbolic variable `offset` takes every value from 0 to 255. For each value, the proof encodes it as a cursor string (base64), decodes it back, and asserts the roundtrip is lossless. If `encode_cursor` and `decode_offset` had any asymmetry -- a rounding error, an off-by-one, a character set mismatch -- the solver would find it.

This proof runs in under a second. It covers 256 input values. A unit test might check 3 or 4 values and hope for the best. The Kani proof covers all of them and is certain.

## When to use Kani

Kani is most valuable for code that is:

- **Security-critical.** If a bug in this function means a privilege escalation, it deserves a proof, not just tests.
- **Pure.** Functions that take inputs and return outputs, without side effects, are ideal for Kani. navra deliberately extracts pure logic from async handlers into separate functions so Kani can verify them.
- **Small-domain.** Functions that operate on small types (enums with a few variants, integers bounded to small ranges) let Kani achieve truly exhaustive verification with no bounds compromise.
- **Hard to test exhaustively.** If the input space has more than a few interesting combinations, hand-written tests will miss some. Kani will not.

Code that is async, I/O-bound, or depends on external state is better served by tests. Kani's strength is mathematical certainty for pure logic; tests' strength is covering the messy real world.

## What Kani cannot prove

Kani is powerful but not omniscient:

- **No unbounded loops.** If your code has a `while` loop with no fixed bound, Kani unrolls it to a configured depth. Properties about the 1001st iteration of a loop with depth bound 1000 are not covered.
- **No async.** Kani operates on synchronous code. navra's async handlers cannot be directly verified. The workaround is to extract pure logic into synchronous functions and prove those.
- **No I/O.** Kani cannot model file systems, networks, or system calls. It proves properties of *computation*, not of interaction with the environment.
- **No concurrency.** Data races, deadlocks, and other concurrency issues are outside Kani's model.
- **No floating point.** Kani's support for floating-point operations is limited. Security-critical code in navra avoids floats for exactly this reason -- IFC labels, rings, and ACL decisions are all integer-based.

These limitations are why navra has 2,500+ tests in addition to 154 proofs. Each verification technique covers different ground. The proof map in `formal/PROOF_MAP.md` documents every proof, the Rust function it verifies, the input space it covers, and whether coverage is exhaustive or bounded. When evaluating navra's verification claims, read the proof map -- it is the authoritative record of what is proven and what is not.

## The cost of proofs

Kani proofs are not free. Each proof takes time to write, time to run, and time to maintain. When the function under verification changes, the proof may need to change too.

In navra's experience, the cost is modest:

- **Writing time.** Most proofs are 5-15 lines of code. The pattern is consistent (declare symbolic inputs, assume bounds, call function, assert property). A developer familiar with the pattern can write a proof in minutes.
- **Run time.** Individual proofs complete in 1-30 seconds. The full suite of 154 proofs takes several minutes. This is comparable to the test suite and is not a bottleneck.
- **Maintenance.** When a function's signature or semantics changes, the proof needs updating. In practice, this happens infrequently for security-critical pure functions, which are designed to be stable interfaces.

The return on investment is high for security-critical code. A Kani proof that takes 10 minutes to write provides a guarantee that no amount of testing can match. For non-security code, the investment makes less sense -- tests are cheaper and cover I/O and async behavior that proofs cannot.

## What's next

Knowing that Kani proofs exist is one thing. Reading one is another. In the next chapter, we walk through a real navra proof line by line -- the capability attenuation proof that ensures child tokens can never exceed parent permissions.
