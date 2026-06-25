+++
title = "Paper Suite Restructuring Decisions"
weight = 10


template = "docs/page.html"
[extra]
toc = true
+++


**Date**: 2026-06-19
**Author**: Fabien Dupont
**Status**: Decided

This document records the structural decisions for the navra paper
suite: which papers stand alone, which fold into the flagship, venue
targets, and submission ordering.

---

## Paper Inventory

| # | File | Title | Current state |
|---|------|-------|---------------|
| 1 | `security-gateway.md` | navra: A Security Microkernel for AI Agent Infrastructure | Flagship. All review notes resolved. 33 refs. |
| 2 | `persona-orchestration.md` | Persona-Driven Multi-Agent Orchestration | Draft complete. 22 refs. Review notes open. |
| 3 | `autonomous-review.md` | Domain-Agnostic Autonomous Review | Draft complete. 12 refs. Most actionable. |
| 4 | `audit-blackbox.md` | Always-On Audit for AI Agent Gateways | Outline with case study. 13 refs. |
| 5 | `model-cards.md` | Composite Model Cards for Agentic AI | Draft complete. 12 refs. |

The flagship paper (`PAPER.md`) is a superset covering the full
architecture. The five papers above are focused extractions.

---

## Verdicts

### Paper 1: security-gateway.md — Standalone

**Verdict**: Standalone.

**Rationale**: This is the flagship workshop paper. All six review
notes are resolved. The three narrowed contributions (gateway-enforced
IFC, capability delegation with attenuation, hash-chained audit)
are distinct and defensible. The FIDES differentiation and MCP
gateway landscape sections position the work clearly.

**Venue target**: ArtSec 2026 (IEEE S&P workshop on AI and
Resilience Technologies). Realistic given the security focus and
formal verification angle.

**Scope boundaries**: Sections 1-10 as written. Does NOT absorb
persona orchestration (Paper 2) or model cards (Paper 5). The
security gateway paper covers the enforcement mechanism; persona
and model selection are userland concerns that belong in separate
papers.

### Paper 2: persona-orchestration.md — Standalone (conditional)

**Verdict**: Standalone, with conditions.

**Rationale**: The space is crowded (PersonaVLM CVPR 2026 Highlight,
MTL, SemaClaw, MorphAgent), but the genotype/phenotype separation
and model-card-driven teammate selection are distinct contributions.
Folding into the flagship would dilute both papers — the security
paper is about enforcement, not cognitive architecture.

**Conditions for submission**:
1. Evaluate on 3-5 external OSS projects across 2+ languages (not
   just navra's own codebase)
2. Ablation study: persona selection vs naive prompts on identical
   models
3. Fix or remove HyDE channel claim (currently a stub)
4. Upgrade memory decay from flat exponential to importance-modulated
   (FadeMem-style) or explicitly position flat decay as a simplicity
   tradeoff

**Venue target**: AAAI 2027 workshop on Autonomous Agents, or
AAMAS 2027. The cognitive framework angle fits agent-focused venues
better than security venues.

**Scope boundaries**: Persona taxonomy, Forge/Weaver architecture,
model card selection, memory, evaluation. Does NOT cover security
enforcement (that's Paper 1). Cross-references Paper 1 for the
gateway context.

### Paper 3: autonomous-review.md — Standalone

**Verdict**: Standalone. Most actionable path to publication.

**Rationale**: Dynamic persona selection for domain-agnostic review
is a clean, testable contribution. The review notes identify a clear
evaluation path (c-CRAB benchmark, 5+ external projects, 3+
languages).

**Contribution list (finalized)**:
- **Keep**: Dynamic persona selection from catalog based on scout
  classification (core contribution)
- **Keep**: Four-stage flow pattern (scout → plan → execute →
  synthesize) as a domain-agnostic review architecture
- **Drop**: JSON parsing resilience (engineering, not research —
  move to implementation details section)
- **Drop**: Flow resumability (engineering — mention briefly, do not
  claim as contribution)

**Conditions for submission**:
1. Run on c-CRAB benchmark [arXiv:2603.23448]
2. Evaluate on 5+ external OSS projects across 3+ languages
3. Compare against CodeAgent (EMNLP 2024) and Code Broker
   (arXiv:2604.23088) baselines
4. Self-review becomes appendix case study only
5. Statistical support: 3+ runs per project, confidence intervals

**Venue target**: ISSTA or ASE workshop, or SCORED (ACM CCS
workshop on Software Supply Chain Offensive Research and Ecosystem
Defenses). The code review evaluation angle fits software
engineering venues.

### Paper 4: audit-blackbox.md — Standalone (short paper)

**Verdict**: Standalone as a short paper or poster.

**Rationale**: The hash-chained blackbox is a clean, self-contained
contribution. The compliance mapping (EU AI Act, SOC2, ISO 42001)
and the file_tree debugging case study make it practical and
concrete. It is too small for a full paper but too distinct to fold
into the flagship without diluting the security focus.

**Why not fold into flagship**: The flagship already references the
blackbox in its three contributions. Making the audit trail a full
section would expand scope beyond the security kernel focus. The
compliance mapping and case study deserve their own spotlight.

**Conditions for submission**:
1. Expand evaluation beyond single case study — add 2-3 more
   debugging scenarios or compliance audit walkthroughs
2. Add performance benchmarks (recording overhead per tool call,
   storage growth rate, chain verification time)
3. The Related Work section (now added) positions against
   tamper-evident logging, flight recorders, and distributed
   observability

**Venue target**: ACSAC poster session, or NSPW (New Security
Paradigms Workshop). The compliance angle fits practitioner-oriented
security venues.

### Paper 5: model-cards.md — Standalone

**Verdict**: Standalone.

**Rationale**: Composite model cards bridge a real gap — no existing
registry provides agentic capability metadata. The three-layer
schema (vendor + agentic + runtime) is a clean contribution. The
upstream path (Kubeflow Model Registry `customProperties`) makes
the work actionable for the MLOps community.

**Why not fold into flagship or persona paper**: Model cards are
infrastructure (like a file format specification), not security
enforcement or cognitive architecture. They serve both papers but
belong to neither.

**Conditions for submission**:
1. Upstream engagement: file Kubeflow Model Registry issue with
   proposed well-known keys
2. Add evaluation across multiple registries (Ollama, HuggingFace,
   OCI) showing auto-population coverage rates
3. User study or survey of ML operators on metadata needs (optional
   but strengthens)

**Venue target**: MLSys 2027 workshop, or NeurIPS Datasets and
Benchmarks track. The registry metadata angle fits ML infrastructure
venues.

---

## Submission Ordering

| Priority | Paper | Venue | Blocking work |
|----------|-------|-------|---------------|
| 1 | autonomous-review (3) | ISSTA/ASE/SCORED | c-CRAB eval, external projects |
| 2 | security-gateway (1) | ArtSec 2026 | Ready (review notes resolved) |
| 3 | audit-blackbox (4) | ACSAC poster / NSPW | More case studies, perf benchmarks |
| 4 | model-cards (5) | MLSys workshop | Upstream Kubeflow issue |
| 5 | persona-orchestration (2) | AAAI/AAMAS workshop | External eval, ablation, HyDE fix |

The autonomous-review paper is prioritized first because:
- Most actionable (clear evaluation path exists)
- Smallest gap between current state and submission-ready
- External benchmarks (c-CRAB) provide objective comparison

The security-gateway paper is second because:
- All review notes resolved — structurally ready
- Venue (ArtSec) aligns with timeline
- May need to update Kani proof count to 146

---

## Dependency Map

```
PAPER.md (flagship, superset)
  ├── security-gateway.md (Paper 1) — standalone
  ├── persona-orchestration.md (Paper 2) — standalone, cross-refs Paper 1
  ├── autonomous-review.md (Paper 3) — standalone, uses persona framework from Paper 2
  ├── audit-blackbox.md (Paper 4) — standalone, referenced by Paper 1 contribution 3
  └── model-cards.md (Paper 5) — standalone, used by Paper 2's model selection
```

No paper depends on another being published first. Each can be
submitted independently. Cross-references use the navra system
description rather than citing unpublished papers.
