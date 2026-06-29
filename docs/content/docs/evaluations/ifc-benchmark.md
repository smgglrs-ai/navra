+++
title = "IFC Adversarial Corpus Benchmark"
weight = 10


template = "docs/page.html"
[extra]
toc = true
+++


Benchmark of navra's information flow control enforcement against
adversarial attack vectors and benign operations.

## Results (2026-06-16)

| Metric | Value |
|--------|-------|
| Overall F1 | 1.000 |
| Precision | 1.000 |
| Recall | 1.000 |
| Attack vectors blocked | 61/61 |
| Benign operations allowed | 200/200 |
| Honest gaps (IFC blocks, safety missed) | 2 |

### By category

| Category | TP | FP | TN | FN | F1 |
|----------|----|----|----|----|-----|
| CommandInjection (MVAR) | 6 | 0 | 0 | 0 | 1.000 |
| EnvironmentAttack (MVAR) | 5 | 0 | 0 | 0 | 1.000 |
| EncodingObfuscation (MVAR) | 8 | 0 | 0 | 0 | 1.000 |
| ShellManipulation (MVAR) | 7 | 0 | 0 | 0 | 1.000 |
| MultiStageAttack (MVAR) | 6 | 0 | 0 | 0 | 1.000 |
| TaintLaundering (navra+MVAR) | 6 | 0 | 0 | 0 | 1.000 |
| TemplateEscape (MVAR) | 5 | 0 | 0 | 0 | 1.000 |
| CredentialTheft (MVAR) | 4 | 0 | 0 | 0 | 1.000 |
| NovelAttack (MVAR) | 4 | 0 | 0 | 0 | 1.000 |
| IfcWriteDown (navra) | 1 | 0 | 0 | 0 | 1.000 |
| TaintAccumulation (navra) | 1 | 0 | 0 | 0 | 1.000 |
| FakeLabelClaim (navra) | 1 | 0 | 0 | 0 | 1.000 |
| FakeDeclassification (navra) | 1 | 0 | 0 | 0 | 1.000 |
| TaintMonotonicity (navra) | 1 | 0 | 0 | 0 | 1.000 |
| ShadowEscape (navra) | 1 | 0 | 0 | 0 | 1.000 |
| PaleFire (navra) | 1 | 0 | 0 | 0 | 1.000 |
| EncodingEvasion (navra) | 2 | 0 | 0 | 0 | 1.000 |
| CharByCharExfil (navra) | 1 | 0 | 0 | 0 | 1.000 |
| Benign | 0 | 0 | 200 | 0 | 1.000 |

### By invariant

| Invariant | Vectors | F1 |
|-----------|---------|-----|
| INV-1 Taint Monotonicity | 7 | 1.000 |
| INV-2 No-Write-Down | 185 | 1.000 |
| INV-3 No-Read-Up | 50 | 1.000 |
| INV-4 Taint Propagation | 18 | 1.000 |
| INV-5 Declassification Safety | 1 | 1.000 |

## Corpus provenance

### navra vectors (11)

Adapted from `navra-server/tests/adversarial_eval.rs` (A7, A10,
B1-B5, C1-C2, D1-D2). ACL-enforced vectors (A1-A6, A8, A9) are
excluded — they test path-based ACL, not IFC label enforcement,
and are covered by the full adversarial_eval integration tests.

### MVAR vectors (50)

Adapted from [mvar-security/mvar](https://github.com/mvar-security/mvar)
v1.5.3 `demo/extreme_attack_suite_50.py`. Apache-2.0 licensed.
9 categories covering command injection, environment attacks,
encoding/obfuscation, shell manipulation, multi-stage attacks,
taint laundering, template escaping, credential theft, and novel
zero-day style attacks.

MVAR's vectors test sink-level enforcement (bash.exec blocked for
untrusted data). navra's equivalent is write-tool enforcement
(file_write, git_commit, http_request blocked for tainted sessions).
The mapping preserves the attack intent while adapting to navra's
architecture.

### Benign vectors (200)

Four groups of 50 vectors testing false-positive resistance:

1. **Clean read-only** — reads trusted data, no write attempted
2. **Untainted writes** — writes without prior external reads
3. **Allow policy** — tainted sessions with Allow policy (writes permitted)
4. **Matching clearance** — writes to targets at matching clearance level

## Methodology

The benchmark evaluates the IFC pipeline at the unit level: no
server spawn, no network, no I/O. Each vector specifies:

- A sequence of `DataLabel` values to absorb (simulating tool reads)
- A `TaintedWritePolicy` (Allow, Approve, or Deny)
- A target `Confidentiality` level for the write
- An optional `ReadClearance` for read-up checks

The harness creates a `TaintTracker`, absorbs labels, checks write
policy, and compares the result to the expected outcome.

### Why F1 = 1.0

navra's IFC is a deterministic reference monitor, not a statistical
classifier. The pipeline enforces structural invariants (Bell-LaPadula
properties) proven correct by Kani model checker. Every read from an
external tool raises session taint. Every write from a tainted
session with Deny policy is blocked. There is no probabilistic
component in the IFC layer itself.

This is by design: the IFC layer guarantees no false negatives for
its invariants. The tradeoff is that IFC cannot detect semantic
attacks (encoded content, paraphrased instructions) — those require
the safety pipeline (L2 similarity, L3 LLM judge) or offline audit
(NeuroTaint-style).

### Honest gaps

Two vectors (D1, D2) are marked as "honest gaps": the safety layer
misses the encoded/homoglyph content, but IFC still blocks the
write because the session was tainted by the external read. This
demonstrates defense-in-depth: IFC catches what content filters miss.

## Comparison with competitors

| System | F1 | Approach | Evaluation scope |
|--------|-----|----------|------------------|
| FIDES | 0.522 | Planner-level lattice IFC | Multi-agent scenarios |
| MVAR | N/A (100% on 50-vector) | Dual-lattice + crypto provenance | Sink-level enforcement |
| NeuroTaint | 0.928 | Semantic + causal + persistent | Offline taint audit |
| **navra** | **1.000** | Gateway-level 2×4 product lattice | Label enforcement (261 vectors) |

Note: these F1 scores are not directly comparable — each system
evaluates on a different corpus with different scope. FIDES measures
end-to-end multi-agent scenarios (harder). NeuroTaint includes
semantic attacks (broader scope). navra's score reflects IFC
enforcement only, not the full pipeline.

## Running the benchmark

```bash
# Full corpus
just test-crate navra-auth

# Integration test with output
cargo test -p navra-auth --test ifc_benchmark -- --nocapture

# Unit tests only
cargo test -p navra-auth -- ifc::corpus::tests ifc::benchmark::tests
```

## Source files

- `navra-auth/src/ifc/corpus.rs` — vector definitions
- `navra-auth/src/ifc/benchmark.rs` — harness and scoring
- `navra-auth/tests/ifc_benchmark.rs` — integration test
