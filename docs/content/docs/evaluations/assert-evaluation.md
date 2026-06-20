+++
title = "ASSERT Evaluation for navra C3"
weight = 10


template = "docs/page.html"
[extra]
toc = true
+++


Evaluation of Microsoft ASSERT (Adaptive Spec-driven Scoring for
Evaluation and Regression Testing) as a complement to Glasswing
for navra's C3 (Correctness, Compliance, Capability) evaluation.

## What ASSERT Does

ASSERT converts natural-language policies into executable test
suites with LLM-as-judge scoring. Released at Build 2026, MIT
licensed, maintained at github.com/responsibleai/ASSERT.

Pipeline:
1. **Specification intake** — natural language policies describing
   desired/undesired agent behavior
2. **Behavior category derivation** — systematizes specs into
   measurable dimensions (following Agarwal et al. 2026)
3. **Test case generation** — single-turn and multi-turn cases
   from derived categories
4. **Inference/execution** — runs cases against target via LiteLLM
   (100+ model endpoints) or Python callables
5. **Judgment/scoring** — LLM judge scores each conversation
   against original policies, with trace-grounded evidence

Core methodology: "AI-assisted systematization" — turning broad
behavior concepts into explicit, measurable specifications.

## OTel Trace Integration

ASSERT can judge pre-collected OpenTelemetry traces without
rerunning inference. If the agent emits OpenInference-compatible
OTel spans, the judge cites tool calls, routing decisions, model
calls, and latency as evidence.

Auto-instrumentation is two lines:
```python
from assert_ai import auto_trace; auto_trace.enable()
```

OpenInference supports 33+ frameworks. For navra, this means ASSERT
could evaluate agent sessions by consuming navra's existing OTel
trace export (built behind the `otel` feature flag) without any
agent-side changes.

## Fit with navra's C3 Framework

### Correctness (C1)

ASSERT's spec-driven approach maps directly to correctness: define
what the agent should do, generate test cases, score results.
navra's tool-call-level OTel traces provide the evidence trail.

**Fit: Strong.** ASSERT handles the "does the agent do what the
policy says" question well. navra's gateway traces give it richer
evidence than most agent frameworks provide.

### Compliance (C2)

ASSERT's policy-to-test pipeline is designed for compliance.
Policies like "never expose credentials," "always use approved
tools," and "respect data classification" translate directly into
ASSERT behavior categories and test cases.

**Fit: Strong.** This is ASSERT's sweet spot. The LLM judge can
cite specific policy violations with trace evidence. The 80-90%
judge-human agreement rate (Microsoft's reported figures) is
sufficient for screening, with human review for high-risk cases.

### Capability (C3)

Capability evaluation ("can the agent accomplish complex tasks")
is less natural for ASSERT, which focuses on policy adherence
rather than task completion quality. Glasswing's adversarial
testing is better suited for probing capability boundaries.

**Fit: Moderate.** ASSERT can test capability through negative
specification ("the agent should be able to handle multi-step
tasks involving X"), but this is not its primary design intent.

## Comparison with Glasswing

| Dimension | ASSERT | Glasswing |
|-----------|--------|-----------|
| Primary mode | Policy compliance | Adversarial probing |
| Test generation | From natural-language specs | Adversarial mutation |
| Scoring | LLM-as-judge | Red-team scoring |
| Trace support | OTel/OpenInference native | Custom |
| Model support | 100+ via LiteLLM | Local models |
| Reproducibility | High (deterministic pipeline) | Lower (adversarial variance) |
| Coverage focus | Known policies | Unknown attack surfaces |

**Complementarity:** ASSERT verifies that the agent meets stated
policies (known-good). Glasswing probes for failures beyond stated
policies (unknown-bad). Together they cover both sides.

## Integration Path for navra

### Phase 1: Policy-Driven Eval (implemented)

Policy specs live in `eval/assert/behaviors/`:

| Spec file | Policy domain |
|-----------|--------------|
| `ifc_enforcement.yaml` | IFC no-read-up / no-write-down / taint propagation |
| `acl_enforcement.yaml` | ACL least-privilege tool access + argument constraints |
| `credential_safety.yaml` | Credential exclusion from tool args and prompts |
| `budget_enforcement.yaml` | Token budget truncation enforcement |

Pipeline config: `eval/assert/configs/navra-compliance.yaml`

Run the evaluation:
```bash
# Full pipeline (systematize → test_set → inference → judge)
just assert-eval

# Validate config only
just assert-check

# Judge pre-collected OTel traces
just assert-eval --traces
```

The pipeline uses `ollama/qwen2.5:7b` for systematization, inference,
and judging. Override with `ASSERT_MODEL` env var.

### Phase 2: CI Integration (planned)

1. Export OTel traces from adversarial_eval test runs as OTLP JSON
2. Run `assert-ai judge-traces` against collected traces in CI
3. Fail CI when compliance score drops below configurable threshold
4. Store ASSERT results alongside test artifacts

### Phase 3: Production Monitoring (future)

1. Continuous evaluation of production OTel traces
2. Dashboard integration with navra's Prometheus metrics
3. Alerting on compliance drift

## Caveats

- **Judge accuracy**: 80-90% agreement with human annotators is
  good for screening but not sufficient as a standalone compliance
  control. Human review remains necessary for high-risk decisions.
- **Non-English**: No published data on judge accuracy for
  non-English agents or specialized domain tasks.
- **navra-specific**: ASSERT's OpenInference instrumentation covers
  agent frameworks (LangChain, CrewAI, etc.), not MCP gateways
  directly. navra's OTel traces would need OpenInference-compatible
  span naming, or ASSERT would judge from raw OTel without semantic
  framework context.
- **Local models**: ASSERT's judge typically uses cloud LLMs (GPT-4,
  Claude). Using local models (Ollama) as judges would need LiteLLM
  configuration and may reduce accuracy.

## Recommendation

**Adopt ASSERT for C2 (Compliance) evaluation.** The spec-driven
approach is a natural fit for navra's policy-heavy architecture.
Start with Phase 1 (policy specs + OTel trace consumption) which
requires minimal integration work.

Keep Glasswing for C3 (Capability) adversarial testing. The two
frameworks are complementary, not competing.

## References

- ASSERT repository: https://github.com/responsibleai/ASSERT
- Methodology: Agarwal et al. (2026), "AI-Assisted Systematization
  for Evaluating GenAI Systems," Microsoft Research
- Open Trust Stack announcement: Build 2026
- OpenInference: https://github.com/Arize-ai/openinference
