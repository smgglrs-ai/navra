+++
title = "22. TLA+ Specifications"
description = "TLA+ proves system behavior over time: session isolation, taint monotonicity, concurrent flow safety. Where Kani proves a function is correct, TLA+ proves the protocol is correct."
weight = 220
template = "docs/page.html"

[extra]
part = "verification"
toc = true
+++

## What you already know

You know that Kani proves properties of individual Rust functions -- for all inputs within bounds, this assertion holds. But some properties are about *sequences of operations over time*: "taint never decreases across any sequence of absorb calls," or "one session's operations never affect another session's state." Kani cannot express these temporal properties. TLA+ can.

## What TLA+ is

TLA+ is a specification language created by Leslie Lamport (the same Lamport behind LaTeX and the Lamport clock). It describes systems as state machines: a set of variables, an initial state, and a set of transitions. TLA+ does not generate code. It does not compile. It is a mathematical language for describing what a system *should do*, independent of how it is implemented.

The TLC model checker takes a TLA+ specification and exhaustively explores every reachable state, checking that invariants hold in every state and temporal properties hold across every sequence of states.

The key difference from Kani: Kani proves properties of a single function call. TLA+ proves properties of sequences of operations -- what happens when multiple agents call tools in arbitrary order, when sessions are created and destroyed, when taint labels accumulate over time.

## navra's TLA+ specifications

navra has 6 TLA+ specifications in the `formal/tla/` directory:

| Specification | What it proves |
|---|---|
| `IFCLattice.tla` | Lattice axioms: join is commutative, associative, idempotent |
| `TaintPropagation.tla` | Taint only increases; no read-up across sessions |
| `SessionIsolation.tla` | One session's absorb never affects another session |
| `CapabilityDelegation.tla` | Delegation chains cannot escalate privileges |
| `FlowConcurrency.tla` | Concurrent label operations maintain lattice properties |
| `VarRefCompleteness.tla` | Variable reference resolution covers all cases |

## Reading SessionIsolation.tla

Let's walk through the session isolation specification. This is the property that matters when multiple agents are connected to navra simultaneously: whatever agent A does to its session state must not change agent B's session state.

```tla
CONSTANTS
    Sessions,       \* Set of session IDs (e.g., {"s1", "s2", "s3"})
    MaxSteps        \* Max steps per session

VARIABLES
    labels,         \* Function: session ID -> DataLabel (as integer 0..7)
    step_count
```

The specification declares constants (configuration parameters) and variables (mutable state). `Sessions` is a set of session IDs. `labels` is a function mapping each session to its current IFC data label (represented as an integer 0..7). `step_count` bounds the exploration.

```tla
Init ==
    /\ labels = [s \in Sessions |-> 0]  \* All sessions start at TRUSTED_PUBLIC (0)
    /\ step_count = 0
```

The initial state: every session starts at label 0 (`TRUSTED_PUBLIC`), and no steps have been taken. The `/\` operator is logical AND -- both conditions must hold simultaneously.

```tla
Absorb(session, new_label) ==
    /\ step_count < MaxSteps
    /\ session \in Sessions
    /\ new_label \in 0..7
    /\ labels' = [labels EXCEPT ![session] = IF new_label > labels[session]
                                             THEN new_label
                                             ELSE labels[session]]
    /\ step_count' = step_count + 1
```

The `Absorb` action models what happens when a session absorbs a new label. The `labels'` notation means "the new value of labels after this step." The `EXCEPT` syntax says: "labels stays the same for all sessions, except for `session`, which gets the maximum of its current label and `new_label`." This is the lattice join operation -- labels only go up, never down.

```tla
Next ==
    \E s \in Sessions : \E l \in 0..7 : Absorb(s, l)
```

The `Next` relation says: in each step, *some* session absorbs *some* label. The existential quantifiers (`\E`) mean TLC will try every possible session and every possible label value at each step. This models the worst case -- an arbitrary interleaving of operations across sessions.

```tla
SessionsIsolated ==
    [][
        \A s1, s2 \in Sessions :
            s1 # s2 =>
                (labels'[s1] # labels[s1] => labels'[s2] = labels[s2])
    ]_labels
```

This is the invariant. In English: "For every pair of different sessions, if session s1's label changed in this step, then session s2's label did not change." The `[]` operator means "in every state" -- this property must hold at every step of every possible execution.

```tla
PerSessionMonotonicity ==
    [][\A s \in Sessions : labels'[s] >= labels[s]]_labels
```

A second invariant: every session's label only increases. Taint is monotonic per session.

## What TLC checks

When you run TLC with `Sessions = {"s1", "s2", "s3"}` and `MaxSteps = 10`, the model checker explores every possible sequence of absorb operations: s1 absorbs label 3, then s2 absorbs label 5, then s1 absorbs label 1, and so on. For 3 sessions, 8 possible labels, and 10 steps, this is millions of states.

TLC reports how many states it explored and whether any invariant was violated:

```
Model checking completed. No error has been found.
  Evaluated 699 distinct states.
  SessionsIsolated: OK
  PerSessionMonotonicity: OK
```

If TLC finds a violation, it reports a trace -- a sequence of states leading to the invariant failure. This trace is a concrete counterexample showing exactly how the system can reach a bad state.

## Temporal logic: liveness and fairness

TLA+ can express temporal properties that go beyond invariants. An invariant says "nothing bad ever happens" (safety). A temporal property can also say "something good eventually happens" (liveness).

For example, you could write a liveness property: "If an agent submits a task, the task eventually reaches a terminal state (completed, failed, or canceled)." This requires a fairness condition -- the specification must assume that the system keeps taking steps and doesn't just stop.

navra's specifications focus on safety properties (invariants) rather than liveness, because the safety properties are what matter for security: taint never decreases, sessions never interfere, privileges never escalate. Liveness is important for correctness ("the server eventually responds") but is harder to prove in an open system where external actors may not cooperate.

## TLA+ vs. Kani: complementary coverage

The two tools cover different territory:

| | Kani | TLA+ |
|---|---|---|
| **Verifies** | Rust functions | State machine specifications |
| **Input model** | All values of Rust types | All sequences of transitions |
| **Temporal properties** | No | Yes |
| **Implementation** | Actual Rust code | Abstract specification |
| **Trust gap** | None (verifies the real code) | Spec must match implementation |

Kani's strength is that it verifies the actual Rust implementation -- no gap between spec and code. TLA+'s strength is that it can reason about sequences of operations, concurrent interleavings, and protocol-level properties.

The trust gap in TLA+ is real: the specification is written by a human who believes it models the implementation correctly. If the specification is wrong, TLC will happily verify properties of a system that doesn't match reality. navra mitigates this by maintaining a proof map (`formal/PROOF_MAP.md`) that explicitly links TLA+ invariants to Rust functions and Kani harnesses. If the TLA+ spec says `labels' = max(labels, new_label)` and the Kani proof verifies the same `join` function, the connection between spec and implementation is documented and cross-checked.

## Other navra specifications

The remaining four TLA+ specifications in navra follow the same pattern:

**IFCLattice.tla** verifies the lattice axioms: join is commutative (`a join b = b join a`), associative (`(a join b) join c = a join (b join c)`), and idempotent (`a join a = a`). It also verifies that join is monotonic with respect to the `can_write_to` relation. This specification has the smallest state space (the lattice has only 8 elements) and TLC verifies it exhaustively in seconds.

**TaintPropagation.tla** models a sequence of absorb operations on a single taint tracker. It verifies that taint is monotonic (never decreases), that PII labels imply sensitive labels, and that the no-read-up invariant holds across sessions. TLC explores 699 distinct states.

**CapabilityDelegation.tla** models delegation chains of capability tokens. It verifies that ring levels never escalate through delegation, that expiry times never extend, and that the on-behalf-of (OBO) flag cannot be added during attenuation. This specification catches a subtle class of bugs: individual delegation steps might be valid, but a chain of steps might accumulate permissions that exceed the root token.

**FlowConcurrency.tla** verifies that concurrent label operations (two sessions absorbing labels simultaneously) maintain lattice properties. This is the specification that motivated the `AtomicU64` representation for labels in the Rust implementation -- the TLA+ model showed that a read-modify-write sequence without atomicity could lose updates.

**VarRefCompleteness.tla** verifies that variable reference resolution covers all cases: valid references are resolved, invalid references produce errors, and the effective label of resolved references is correctly computed as the join of all referenced values' labels.

## Running TLC

navra's TLA+ specifications include configuration files (`.cfg`) that define constants and what TLC should check. Running them requires the TLA+ Toolbox or the `tlc` command-line tool:

```bash
cd formal/tla
java -jar /path/to/tla2tools.jar SessionIsolation.tla
```

TLC prints the number of distinct states explored, the number of states checked per second, and whether any invariant was violated. For navra's specifications, verification completes in under a minute on a modern laptop.

The specifications are not part of the build process or CI pipeline. They are verified by maintainers when the protocol or security model changes. This is a deliberate choice: TLA+ requires the Java-based TLA+ tools, and adding a JVM dependency to CI for 6 specifications that change infrequently is not worth the complexity.

## What's next

Proofs and model checking are powerful but have bounds. Property testing and integration tests fill the gaps that formal methods cannot reach. The next chapter covers navra's testing pyramid and where each technique contributes.
