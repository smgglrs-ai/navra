# Formal Verification Proof Map

Maps TLA+ invariants to Rust implementations and Kani harnesses.

## Lattice Properties

| TLA+ (IFCLattice.tla) | Rust function | Kani harness | Coverage |
|---|---|---|---|
| JoinCommutative | `DataLabel::join` (label.rs) | `join_is_commutative` | Exhaustive (8²) |
| JoinAssociative | `DataLabel::join` (label.rs) | `join_is_associative` | Exhaustive (8³) |
| JoinIdempotent | `DataLabel::join` (label.rs) | `join_is_idempotent` | Exhaustive (8) |
| JoinMonotonic | `DataLabel::join` (label.rs) | `join_is_monotonic` | Exhaustive (8²) |
| NoWriteDownTransitive | `DataLabel::can_write_to` | `no_write_down_is_transitive` | Exhaustive (8×4²) |
| JoinPreservesWriteRestriction | `join` + `can_write_to` | `join_preserves_write_restriction` | Exhaustive (8²×4) |
| — | `DataLabel::can_write_to` | `no_write_down_holds` | Exhaustive (8×4) |
| — | `DataLabel::can_read_from` | `no_read_up_holds` | Exhaustive (4²) |
| — | `DataLabel::can_read_from` | `no_read_up_is_transitive` | Exhaustive (4³) |
| — | `can_write_to` + `can_read_from` | `blp_dual_properties_consistent` | Exhaustive (8×4) |

## Taint Propagation

| TLA+ (TaintPropagation.tla) | Rust function | Kani harness | Coverage |
|---|---|---|---|
| TaintMonotonicity | `TaintTracker::absorb` | `taint_never_decreases` | Exhaustive (8) |
| TaintMonotonicity (sequence) | `TaintTracker::absorb` (×3) | `taint_monotonic_over_sequence` | Exhaustive (8³) |
| NoReadUpInv | `ReadClearance` check (handlers.rs) | — | TLC (699 states) |
| — | `TaintTracker::is_pii/is_sensitive` | `pii_implies_sensitive` | Exhaustive (8) |
| — | `TaintTracker::absorb` = `join` | `absorb_is_join` | Exhaustive (8²) |
| Session persistence | `update_context_label` (session.rs) | (compositionality: uses same `join`) | By construction |

## Deny-Wins ACL

| Property | Rust function | Kani harness | Coverage |
|---|---|---|---|
| Deny always wins | `deny_wins_eval` (acl.rs) | `deny_always_wins` | Exhaustive (2³) |
| No allow = denied | `deny_wins_eval` (acl.rs) | `no_allow_means_denied` | Exhaustive (2) |
| Allow without deny succeeds | `deny_wins_eval` (acl.rs) | `allow_without_deny_succeeds` | Exhaustive (1) |
| Full decision table | `deny_wins_eval` (acl.rs) | `deny_wins_exhaustive` | Exhaustive (2³) |

## Capability Delegation

| TLA+ (CapabilityDelegation.tla) | Rust function | Kani harness | Coverage |
|---|---|---|---|
| NoRingEscalation | `check_attenuation` | `ring_escalation_rejected` | Bounded (ring 0..3) |
| — | `check_attenuation` | `valid_ring_accepted` | Bounded (ring 0..3) |
| NoExpiryExtension | `check_attenuation` | `expiry_extension_rejected` | Bounded (exp 0..10000) |
| — | `check_attenuation` | `valid_expiry_accepted` | Bounded (exp 0..10000) |
| TransitiveAttenuation | `check_attenuation` (×2) | `transitive_attenuation` | Bounded (3 levels) |
| NoOperationEscalation | `validate_delegation` | — (unit tests) | Test coverage |
| NoCredentialEscalation | `validate_delegation` | — (unit tests) | Test coverage |

## Session Isolation

| TLA+ (SessionIsolation.tla) | Rust function | Coverage |
|---|---|---|
| SessionsIsolated | `InMemorySessionBackend::update_context_label` | TLC (41,473 states, 3 sessions) |
| PerSessionMonotonicity | `InMemorySessionBackend::update_context_label` | TLC (41,473 states) |

## Blackbox Hash Chain

| Property | Rust function | Verification | Coverage |
|---|---|---|---|
| Preimage determinism | `chain_preimage` (blackbox.rs) | Unit test | Concrete |
| Any-field modification changes preimage | `chain_preimage` (blackbox.rs) | Unit test (5 fields) | Concrete |
| Tampered entry detected | `verify_chain_link` (blackbox.rs) | Unit test | Concrete |
| Chain integrity across restarts | `Blackbox::verify_chain` | Integration test | E2E |

## Hook Pipeline Fail-Closed

| Property | Code location | Verification |
|---|---|---|
| Pre-hook timeout blocks | `run_pre` (pipeline.rs:52-64) | By construction (`unwrap_or_else → Block`) |
| Post-hook timeout blocks | `run_post` (pipeline.rs:108-120) | By construction (`unwrap_or_else → Block`) |

## Approval Single-Use

| Property | Rust function | Verification |
|---|---|---|
| Grant consumed on check | `check_grant` (approval.rs:140) | By construction (`remove(pos)`) |
| Expired grants pruned | `check_grant` (approval.rs:134) | By construction (`retain`) |
| Second check returns false | `check_grant` + integration test | E2E test |

## OAuth Scope Mapping

| Property | Rust function | Verification |
|---|---|---|
| Unknown scope → readonly | `resolve_permissions_from_scopes` | Unit test |
| No escalation beyond mapped scopes | `resolve_permissions_from_scopes` | Unit test (exhaustive) |

## Variable Reference Completeness

| TLA+ (VarRefCompleteness.tla) | Rust function | Coverage |
|---|---|---|
| SingleRefIdentity | `resolve_variable_refs` | TLA+ model |
| TwoRefJoin | `resolve_variable_refs` | TLA+ model |
| AdditionalRefMonotonic | `resolve_variable_refs` | TLA+ model |
| JoinIsCorrectForAllSubsets | `resolve_variable_refs` | TLA+ model |

## Bell-LaPadula Coverage

Both BLP properties are formally verified:

| Property | Direction | Rust function | Kani | TLA+ |
|---|---|---|---|---|
| *-Property (no write-down) | High→Low blocked | `can_write_to` | `no_write_down_holds` | IFCLattice |
| Simple Security (no read-up) | Low→High blocked | `can_read_from` + `ReadClearance` | `no_read_up_holds` | TaintPropagation |

## TLC Model Check Results

| Spec | States | Distinct | Invariants | Result |
|---|---|---|---|---|
| IFCLattice | 2 | 1 | 6 ASSUME properties | PASS |
| TaintPropagation (Deny, Sensitive) | 699 | 285 | TypeOK, NoReadUpInv | PASS |
| SessionIsolation (3 sessions) | 41,473 | 2,240 | SessionsIsolated, PerSessionMonotonicity | PASS |

## Summary

| Component | Kani | TLA+ | Unit/Integration | Total properties |
|---|---|---|---|---|
| Lattice (label.rs) | 10 | 6 | 7 | 23 |
| Taint (ifc/mod.rs) | 4 | 4 | 8 | 16 |
| ACL (acl.rs) | 4 | — | 15 | 19 |
| Capability (capability.rs) | 5 | 5 | 12 | 22 |
| Session (session.rs) | — | 2 | 6 | 8 |
| Blackbox (blackbox.rs) | — | — | 8 | 8 |
| Hooks (pipeline.rs) | — | — | 2 (structural) | 2 |
| Approval (approval.rs) | — | — | 3 | 3 |
| OAuth (oauth.rs) | — | — | 3 | 3 |
| Var-ref (value_store.rs) | — | 4 | 8 | 12 |
| **Total** | **23** | **21** | **72** | **116** |
