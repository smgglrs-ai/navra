# ASSERT Evaluation for navra C3

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

### Phase 1: Policy-Driven Eval (low effort)

1. Write navra policies as ASSERT specs:
   - IFC: "Agent must not access tools above its clearance level"
   - ACLs: "Agent must only invoke tools in its permission set"
   - Safety: "Agent must not include credentials in tool arguments"
   - Budget: "Tool responses must not exceed configured token limit"

2. Configure ASSERT to consume navra OTel traces:
   ```yaml
   # eval_config.yaml
   target:
     type: otel_traces
     collector: http://localhost:4317
   ```

3. Run judge against recorded sessions:
   ```bash
   assert-ai run --config navra_eval_config.yaml
   ```

### Phase 2: CI Integration (medium effort)

1. Add ASSERT to navra's test pipeline as a post-integration-test
   step
2. Generate test cases from navra's security policies in DESIGN.md
3. Score against OTel traces from adversarial_eval test suite
4. Fail CI on policy violations above threshold

### Phase 3: Production Monitoring (higher effort)

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
