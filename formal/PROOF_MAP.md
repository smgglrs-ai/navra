# Formal Verification Proof Map

Maps TLA+ invariants, Kani harnesses, and Verus proofs to Rust implementations.

Verus proofs live inline in the source files inside `verus!{}` blocks.
Ghost code (spec fn, proof fn) is erased at compile time — `cargo build`
is unaffected. Run `scripts/run-verus.sh` or `cargo-verus verus verify`
to check proofs.

## Lattice Properties

| TLA+ (IFCLattice.tla) | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| JoinCommutative | `DataLabel::join` (label.rs) | `join_is_commutative` | `join_is_commutative` | Bounded + Unbounded |
| JoinAssociative | `DataLabel::join` (label.rs) | `join_is_associative` | `join_is_associative` | Bounded + Unbounded |
| JoinIdempotent | `DataLabel::join` (label.rs) | `join_is_idempotent` | `join_is_idempotent` | Bounded + Unbounded |
| JoinMonotonic | `DataLabel::join` (label.rs) | `join_is_monotonic` | `join_is_monotonic` | Bounded + Unbounded |
| NoWriteDownTransitive | `DataLabel::can_write_to` | `no_write_down_is_transitive` | `no_write_down_is_transitive` | Bounded + Unbounded |
| JoinPreservesWriteRestriction | `join` + `can_write_to` | `join_preserves_write_restriction` | `join_preserves_write_restriction` | Bounded + Unbounded |
| — | `DataLabel::can_write_to` | `no_write_down_holds` | `no_write_down_holds` | Bounded + Unbounded |
| — | `DataLabel::can_read_from` | `no_read_up_holds` | `no_read_up_holds` | Bounded + Unbounded |
| — | `DataLabel::can_read_from` | `no_read_up_is_transitive` | `no_read_up_is_transitive` | Bounded + Unbounded |
| — | `can_write_to` + `can_read_from` | `blp_dual_properties_consistent` | `blp_dual_properties_consistent` | Bounded + Unbounded |
| — | — | — | `trusted_public_is_bottom` | Unbounded |
| — | — | — | `untrusted_secret_is_top` | Unbounded |

## Taint Propagation

| TLA+ (TaintPropagation.tla) | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| TaintMonotonicity | `TaintTracker::absorb` | `taint_never_decreases` | `taint_monotonicity` | Bounded + Unbounded |
| TaintMonotonicity (sequence) | `TaintTracker::absorb` (×3) | `taint_monotonic_over_sequence` | `taint_monotonic_over_sequence` | Bounded + Unbounded |
| NoReadUpInv | `ReadClearance` check (handlers.rs) | — | — | TLC (699 states) |
| — | `TaintTracker::is_pii/is_sensitive` | `pii_implies_sensitive` | — | Exhaustive (8) |
| — | `TaintTracker::absorb` = `join` | `absorb_is_join` | `absorb_is_join` | Bounded + Unbounded |
| — | `is_pii` ⇒ `is_sensitive` | `pii_implies_sensitive` | `pii_implies_sensitive` | Bounded + Unbounded |
| — | `declassify()` | `declassify_only_steps_down` | `declassify_only_steps_down` | Bounded + Unbounded |
| — | IFC noninterference | `noninterference_write_decision` | `noninterference_write_decision` | Bounded + Unbounded |
| Session persistence | `update_context_label` (session.rs) | (compositionality: uses same `join`) | — | By construction |

## Deny-Wins ACL

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Deny always wins | `deny_wins_eval` (acl.rs) | `deny_always_wins` | `deny_always_wins` | Bounded + Unbounded |
| No allow = denied | `deny_wins_eval` (acl.rs) | `no_allow_means_denied` | `no_allow_means_denied` | Bounded + Unbounded |
| Allow without deny succeeds | `deny_wins_eval` (acl.rs) | `allow_without_deny_succeeds` | `allow_without_deny_succeeds` | Bounded + Unbounded |
| Full decision table | `deny_wins_eval` (acl.rs) | `deny_wins_exhaustive` | `deny_wins_exhaustive` | Bounded + Unbounded |
| Deny accumulation monotonic | `apply_ring_inheritance` | — | `deny_accumulation_monotonic` | Unbounded |
| Higher ring never grants more | `apply_ring_inheritance` | — | `higher_ring_never_grants_more` | Unbounded |

## Capability Delegation

| TLA+ (CapabilityDelegation.tla) | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| NoRingEscalation | `check_attenuation` | `ring_escalation_rejected` | `ring_escalation_rejected` | Bounded + Unbounded |
| — | `check_attenuation` | `valid_ring_accepted` | `valid_ring_accepted` | Bounded + Unbounded |
| NoExpiryExtension | `check_attenuation` | `expiry_extension_rejected` | `expiry_extension_rejected` | Bounded + Unbounded |
| — | `check_attenuation` | `valid_expiry_accepted` | `valid_expiry_accepted` | Bounded + Unbounded |
| TransitiveAttenuation | `check_attenuation` (×2) | `transitive_attenuation` | `transitive_attenuation` | Bounded + Unbounded |
| — | `check_obo_attenuation` | `obo_escalation_rejected` | `obo_escalation_rejected` | Bounded + Unbounded |
| — | `check_sandbox_escalation` | `sandbox_removal_rejected` | `sandbox_removal_rejected` | Bounded + Unbounded |
| NoOperationEscalation | `validate_delegation` | — (unit tests) | — | Test coverage |
| NoCredentialEscalation | `validate_delegation` | — (unit tests) | — | Test coverage |

## Session Isolation

| TLA+ (SessionIsolation.tla) | Rust function | Coverage |
|---|---|---|
| SessionsIsolated | `InMemorySessionBackend::update_context_label` | TLC (3 sessions) |
| PerSessionMonotonicity | `InMemorySessionBackend::update_context_label` | TLC (3 sessions) |
| InFlightNeverExpired | `expire` guarded by `in_flight` check | TLC (3 sessions, MaxSteps=10) |
| ToolCallReadsValidLabel | `get` during tool dispatch | TLC (3 sessions, MaxSteps=10) |

## Blackbox Hash Chain

| Property | Rust function | Verification | Verus proof | Coverage |
|---|---|---|---|---|
| Preimage determinism | `chain_preimage` (blackbox.rs) | Unit test | `preimage_determinism` | Concrete + Unbounded |
| Any-field modification changes preimage | `chain_preimage` (blackbox.rs) | Unit test (5 fields) | `field_independence_*` (7 proofs) | Concrete + Unbounded |
| Tampered entry detected | `verify_chain_link` (blackbox.rs) | Unit test | `chain_link_tamper_detection` | Concrete + Unbounded |
| Sequence monotonicity | `Blackbox::record_with_obo` | Kani: `seq_increment_monotonic` | `seq_monotonicity` | Bounded + Unbounded |
| Truncate never exceeds max | `truncate` (blackbox.rs) | Kani: `truncate_never_exceeds_max` | `truncate_never_exceeds_max` | Bounded + Unbounded |
| Truncate within budget is identity | `truncate` (blackbox.rs) | Kani: `truncate_within_budget_is_identity` | `truncate_within_budget_is_identity` | Bounded + Unbounded |
| Chain integrity across restarts | `Blackbox::verify_chain` | Integration test | — | E2E |

## Tool Scanner Verdict Aggregation

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Critical → Malicious | `aggregate_verdict` | `critical_implies_malicious` | `critical_implies_malicious` | Bounded + Unbounded |
| High (no Critical) → Suspicious | `aggregate_verdict` | `high_without_critical_implies_suspicious` | `high_without_critical_implies_suspicious` | Bounded + Unbounded |
| No High/Critical → Safe | `aggregate_verdict` | `no_high_no_critical_implies_safe` | `no_high_no_critical_implies_safe` | Bounded + Unbounded |

## Risk Tier Classification

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Rank is total order | `RiskLevelThreshold::Ord` | `rank_is_total_order` | `rank_is_total_order` | Bounded + Unbounded |
| Classify is monotonic | `RiskTierConfig::classify` | `classify_monotonic` | `classify_monotonic` | Bounded + Unbounded |
| Valid config: auto ≤ approval | `RiskTierConfig::is_valid` | `valid_config_auto_below_approval` | `valid_config_auto_below_approval` | Bounded + Unbounded |
| Classify safe even if invalid | `RiskTierConfig::classify` | `classify_safe_even_if_invalid` | `classify_safe_even_if_invalid` | Bounded + Unbounded |

## Trust Score

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Score bounded after success | `trust_transition` | `score_bounded_after_success` | `score_bounded_after_success` | Bounded + Unbounded |
| Score bounded after penalty | `trust_transition` | `score_bounded_after_penalty` | `score_bounded_after_penalty` | Bounded + Unbounded |
| State thresholds monotonic | `classify_state` | `state_thresholds_monotonic` | `state_thresholds_monotonic` | Bounded + Unbounded |
| Decay multiplication bounded | manual | `decay_multiplication_bounded` | `decay_multiplication_bounded` | Bounded + Unbounded |

## Sandbox Profile

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Simulate weakening rejected | `check_action_attenuation` | `simulate_weakening_rejected` | `simulate_weakening_rejected` | Bounded + Unbounded |
| Rate limit escalation rejected | `check_action_attenuation` | `rate_limit_escalation_rejected` | `rate_limit_escalation_rejected` | Bounded + Unbounded |
| Rate limit tightening accepted | `check_action_attenuation` | `rate_limit_tightening_accepted` | `rate_limit_tightening_accepted` | Bounded + Unbounded |
| Non-simulate parent accepts any | `check_action_attenuation` | `non_simulate_parent_any_child_accepted` | `non_simulate_parent_any_child_accepted` | Bounded + Unbounded |

## Authentication

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| CT eq correct | `constant_time_eq` | `ct_eq_correct` | `ct_eq_correct` | Bounded + Unbounded |
| CT eq different lengths false | `constant_time_eq` | `ct_eq_different_lengths_false` | `ct_eq_different_lengths_false` | Bounded + Unbounded |

## Pagination

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Offset past end → empty | `paginate_pure` | `paginate_offset_past_end_empty` | `paginate_offset_past_end_empty` | Bounded + Unbounded |
| Page size bounded | `paginate_pure` | `paginate_page_size_bounded` | `paginate_page_size_bounded` | Bounded + Unbounded |

## Metrics Counters

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Counter monotonic | `counter_add` | `counter_monotonic` | `counter_monotonic` | Bounded + Unbounded |
| Zero delta unchanged | `counter_add` | `counter_zero_delta_unchanged` | `counter_zero_delta_unchanged` | Bounded + Unbounded |

## Hook Pipeline Fail-Closed

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Block short-circuits | `pre_dispatch` | `block_always_short_circuits` | `block_always_short_circuits` | Bounded + Unbounded |
| Simulate short-circuits | `pre_dispatch` | `simulate_always_short_circuits` | `simulate_always_short_circuits` | Bounded + Unbounded |
| ModifyResult ignored in pre | `pre_dispatch` | `modify_result_ignored_in_pre_phase` | `modify_result_ignored_in_pre_phase` | Bounded + Unbounded |
| Timeout → Block | `pre_dispatch` | `timeout_is_fail_closed` | `timeout_is_fail_closed` | Bounded + Unbounded |

## Statistical Guardrails

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Window never exceeds max | `bounded_push` | `window_never_exceeds_max` | `window_never_exceeds_max` | Bounded + Unbounded |

## Flow Validation

| Property | Rust function | Kani harness | Verus proof | Coverage |
|---|---|---|---|---|
| Score in bounds | `compute_score` | `score_in_bounds` | `score_in_bounds` | Bounded + Unbounded |
| Score monotonic in penalties | `compute_score` | `score_monotonic_in_penalties` | `score_monotonic_in_penalties` | Bounded + Unbounded |
| Threshold correct | `compute_score` | `threshold_correct` | `threshold_correct` | Bounded + Unbounded |
| Dominator self in set | `dom_intersect_step` | `dominator_self_always_in_set` | `dominator_self_always_in_set` | Bounded + Unbounded |
| Always condition true | `evaluate_condition` | `always_condition_always_true` | `always_condition_always_true` | Bounded + Unbounded |
| Max iterations respected | `should_activate` | `should_activate_respects_max_iterations` | `should_activate_respects_max_iterations` | Bounded + Unbounded |
| All failures bounded retries | `get_strategy` | `all_failures_have_bounded_retries` | `all_failures_have_bounded_retries` | Bounded + Unbounded |
| Circular fix never retries | `get_strategy` | `circular_fix_never_retries` | `circular_fix_never_retries` | Bounded + Unbounded |
| Circular fix requires threshold | `detect_circular_fix` | `circular_fix_requires_threshold` | `circular_fix_requires_threshold` | Bounded + Unbounded |
| Default clearance restrictive | `resolve_clearance` | `default_clearance_is_maximally_restrictive` | `default_clearance_is_maximally_restrictive` | Bounded + Unbounded |
| IFC consistent with BLP | `can_write_to` | `ifc_check_consistent_with_can_write_to` | `ifc_check_consistent_with_can_write_to` | Bounded + Unbounded |

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
| SessionIsolation (3 sessions, MaxSteps=10) | 1,665,217 | 101,952 | SessionsIsolated, PerSessionMonotonicity, InFlightNeverExpired, ToolCallReadsValidLabel | PASS |

## Summary

| Component | Kani | TLA+ | Verus | Unit/Integration | Total properties |
|---|---|---|---|---|---|
| Lattice (label.rs) | 10 | 6 | 19 | 7 | 42 |
| Taint (ifc/mod.rs) | 7 | 4 | 10 | 8 | 29 |
| ACL (acl.rs) | 4 | — | 8 | 15 | 27 |
| Capability (capability.rs) | 8 | 5 | 8 | 12 | 33 |
| Tool scanner (tool_scanner.rs) | 5 | — | 3 | 10 | 18 |
| Tool rules (tool_rules.rs) | — | — | 4 | 10 | 14 |
| Disclosure (disclosure.rs) | — | — | 4 | 5 | 9 |
| Domain rules (domain_rules.rs) | — | — | 4 | 8 | 12 |
| Resource class (resource_class.rs) | — | — | 5 | 10 | 15 |
| Risk tier (risk_tier.rs) | 6 | — | 4 | 6 | 16 |
| Trust score (trust_score.rs) | 6 | — | 4 | 6 | 16 |
| Sandbox (sandbox_profile.rs) | 4 | — | 4 | 8 | 16 |
| Auth (mod.rs) | 2 | — | 2 | 4 | 8 |
| Rate limiter (quota.rs) | — | — | 5 | 6 | 11 |
| Manifest TOFU (manifest.rs) | — | — | 7 | 6 | 13 |
| Session grants (session.rs) | — | — | 6 | 8 | 14 |
| Pagination (mcp.rs) | 3 | — | 2 | 4 | 9 |
| Value store (value_store.rs) | — | — | 3 | 8 | 11 |
| Gate pipeline (handlers.rs) | — | — | 10 | — | 10 |
| Agent action (action.rs) | 3 | — | 3 | 4 | 10 |
| Agent quota (quota.rs) | 1 | — | 1 | 4 | 6 |
| Budget (budget.rs) | 5 | — | 2 | 4 | 11 |
| Model backoff (lib.rs) | 3 | — | 1 | 4 | 8 |
| PII regex (regex.rs) | 8 | — | 2 | 10 | 20 |
| Exec tools (exec_tools.rs) | 3 | — | 1 | 4 | 8 |
| Session context (session.rs) | — | 4 | 5 | 6 | 15 |
| Blackbox (blackbox.rs) | 5 | — | 14 | 8 | 27 |
| Metrics (metrics.rs) | 2 | — | 2 | 4 | 8 |
| Hooks pipeline (pipeline.rs) | 4 | — | 9 | 2 | 15 |
| Statistical (statistical.rs) | 2 | — | 1 | 4 | 7 |
| Temporal contract (temporal_contract.rs) | 4 | — | 4 | 8 | 16 |
| Flow validation (dominator/mandate) | 7 | — | 4 | 8 | 19 |
| Backedge (backedge.rs) | 2 | — | 2 | 4 | 8 |
| Recovery (recovery.rs) | 3 | — | 3 | 4 | 10 |
| Mesh IFC (mesh.rs) | 2 | — | 2 | 4 | 8 |
| Approval (approval.rs) | — | — | — | 3 | 3 |
| OAuth (oauth.rs) | — | — | — | 3 | 3 |
| **Total** | **109** | **23** | **168** | **186** | **486** |
