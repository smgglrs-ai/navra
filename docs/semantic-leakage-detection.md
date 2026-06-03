# Leakage Detection: Similarity (L2) + Semantic Analysis (L3)

## The problem

Gateway-level IFC tracks data labels at tool-call boundaries.
When an agent reads tainted content and reveals information from
it in a subsequent tool call, there are three levels of leakage
that require different detection techniques:

| Level | Technique | Example | Detection |
|---|---|---|---|
| Exact copy | "hunter2" → "hunter2" | L1 (IFC labels) or regex |
| Paraphrase | "the DB password is hunter2" → "database credential: hunter2" | **L2 (embedding similarity)** |
| Derived info | "hunter2" → "starts with h, 7 chars" | **L3 (LLM judge)** |

No published IFC system addresses L2 or L3 in real-time.

## L2 — Similarity-based detection (`SimilarityLeakageHook`)

Compares outgoing tool arguments against tainted values using
embedding cosine similarity. Catches paraphrases and reformulations.

### Benchmark results

4 embedding models tested on 13 scenarios (threshold 0.75):

| Model | Params | Precision | Recall | Latency |
|---|---|---|---|---|
| MiniLM-L6-v2 | 22M | 100% | 57% | 11ms |
| **BGE-large-v1.5** | **335M** | **100%** | **100%** | **39ms** |
| Stella-v5 | 1.5B | 100% | 100% | 128ms |
| PPLX-embed-v1 | 4B | 100% | 43% | 323ms |

Performance peaks at 335M. Larger models degrade because they
are optimized for document retrieval, not sentence-level
paraphrase detection. BGE-large-v1.5 is the recommended model.

### What L2 catches

- Exact copies (sim ~1.0)
- Minor rephrasing (sim ~0.99)
- Partial PII extraction (sim ~0.81-0.86)
- Synonym substitution (sim ~0.77-0.90)
- Reformatted data (sim ~0.73-0.89)
- Entity reformulation (sim ~0.55-0.76)

### What L2 cannot catch

- Derived information ("starts with h, 7 chars") — sim ~0.35
- Indirect descriptions with no vocabulary overlap
- Encoded content that was decoded before paraphrasing

### Architecture

```
Write tool call
    │
    ├── L2: SimilarityLeakageHook (pre_tool_use)
    │   ├── Embed outgoing text (ONNX, ~40ms)
    │   ├── Compare against tainted ValueStore entries
    │   └── Block if similarity > 0.75
    │
    └── Continue to tool execution
```

Runs on every write tool call. Only compares against values
with confidentiality >= Sensitive. ~40ms overhead per write.

## L3 — Semantic analysis (`SemanticLeakageJudge`)

Asks an LLM judge: "Does this outgoing text reveal any
information that could be derived from the following
tainted content?" Catches derived information that similarity
cannot detect.

### Two modes

**Inline (selective):** Runs on write tools when session
confidentiality >= Secret. Only fires for the highest-risk
writes — you pay ~500ms+ per call but only on a fraction of
tool calls. Complements L2 which runs on all writes.

**Continuous async:** Runs outside the agent's latency chain.
After every write tool call, L3 analyzes it via `tokio::spawn`
— the write proceeds immediately, L3 runs in the background.
If leakage is detected:
1. Audit log entry is written immediately
2. Session trust score is penalized (`record_safety_trigger()`)
3. Session taint is retroactively elevated so L1 blocks
   subsequent writes
4. Operator is notified via D-Bus/webhook

Same pattern as navra's cognitive file integrity monitor
(background task, 60s interval, non-blocking). Unlike
NeuroTaint which runs post-hoc, navra's L3 continuous mode
can intervene mid-session by escalating the taint level.

### What L3 catches that L2 cannot

- "the password starts with h and is 7 characters"
- "the API key prefix is sk-ant"
- "annual compensation is approximately one hundred fifty thousand"
- Encoded content that has been decoded and described

### Architecture

```
Write tool call
    │
    ├── L2: SimilarityLeakageHook (~40ms, all writes, blocking)
    │
    ├── L3 inline: SemanticLeakageJudge (~500ms+, Secret writes, blocking)
    │   ├── Build prompt: "Does {outgoing} reveal info from {tainted}?"
    │   ├── Call judge model (NOT the agent's model)
    │   └── Block if confidence > 0.7
    │
    ├── Tool executes (L2/L3 inline passed)
    │
    └── L3 continuous: tokio::spawn (async, non-blocking)
        ├── Same judge prompt, runs in background
        ├── If leakage detected:
        │   ├── record_safety_trigger() → trust score drops
        │   ├── taint.absorb(Secret) → L1 blocks future writes
        │   ├── audit log entry written
        │   └── operator notified (D-Bus/webhook)
        └── Agent continues unaware — next write will be blocked by L1
```

### Judge model requirements

- Must NOT be the agent's own model (avoids self-evaluation
  circularity — the agent would judge its own exfiltration
  favorably)
- Small model sufficient (~1-3B) — binary classification task
- Can be the same ONNX model used for safety classification
- Prompt: structured, not conversational:
  ```
  Tainted content: {tainted_text}
  Outgoing text: {outgoing_text}
  Question: Does the outgoing text reveal, describe, or encode
  any information from the tainted content? Answer 0.0-1.0.
  ```

### Performance budget

| Tier | Trigger | Latency added | Coverage |
|---|---|---|---|
| L1 (IFC labels) | All tool calls | <1us | Exact flow control |
| L2 (similarity) | Write tools | ~40ms | Paraphrases |
| L3 inline (judge) | Secret writes only | ~500ms+ | Derived info, blocking |
| L3 continuous (judge) | All writes, async | 0 (background) | Derived info, retroactive |

The operator configures which tiers are active per permission
set. Default: L1 + L2. High-security: L1 + L2 + L3 inline.
Standard: L1 + L2 + L3 continuous.

### Comparison to NeuroTaint

NeuroTaint (arXiv:2604.23374) achieves F1=0.928 on semantic
taint detection using offline causal influence analysis. navra's
L3 out-of-band mode provides similar post-hoc analysis using
the existing blackbox transcript. The key differences:

- NeuroTaint analyzes token-level causal influence (requires
  model internals). navra analyzes tool-call-level transcripts
  (no model access needed).
- NeuroTaint runs post-hoc only. navra's L3 inline mode
  provides real-time blocking on high-risk writes.
- NeuroTaint operates on a single agent. navra's blackbox
  covers multi-agent flows via navra-flow.

## Policy learning from denials (`navra policy suggest`)

SELinux's `audit2allow` solved the cold-start problem: instead
of writing policies from scratch, operators deploy in permissive
mode, collect denials, and generate allow rules from them.

navra's blackbox records every denial with full context:
```sql
SELECT agent_permissions, tool_name, tool_args, outcome, ifc_label
FROM blackbox_entries
WHERE outcome LIKE 'denied_%'
ORDER BY timestamp_ms DESC
```

`navra policy suggest` reads these denials and generates:

**Cedar rules:**
```cedar
// 12 denials: agent "reviewer" tried file_read on /src/**
// Outcome: denied_acl (not in allow list)
permit(
    principal == Agent::"reviewer",
    action == Action::"file_read",
    resource
) when { context.path_prefix == "/src/" };
```

**TOML ACL entries:**
```toml
# 8 denials: agent "builder" tried git_commit
# Outcome: denied_acl (operation "commit" not in operations list)
[permissions.builder]
operations = ["read", "write", "commit"]  # was: ["read", "write"]
```

**IFC exemptions:**
```toml
# 5 denials: agent "reporter" tried file_write after reading
# tainted data. All writes were to /reports/** (approved target).
# Suggestion: add trusted path for /reports/**
[permissions.reporter]
trusted_paths = ["/reports/**"]
```

The operator reviews each suggestion — like `audit2allow`,
the tool generates candidates, not final policy. Dangerous
suggestions (e.g., "allow exec_command for untrusted agent")
are flagged with warnings.

**Leakage policy feedback loop:** When L2/L3 blocks a write
that the operator determines was legitimate, the operator can:
1. Lower the similarity threshold for that agent/tool pair
2. Add the specific (tainted_value, outgoing_text) pair to an
   allowlist (this text pattern is known-safe despite similarity)
3. Adjust the L3 judge prompt with org-specific context

This closes the feedback loop: denials → suggestions → review
→ refined policy → fewer false blocks.

### Novel contribution

No published system combines real-time similarity detection (L2)
with selective LLM-based semantic analysis (L3) at the gateway
layer. NeuroTaint is offline-only. FIDES and CaMeL don't address
information leakage through LLM reasoning at all. navra provides
a configurable three-tier defense:

1. L1: deterministic (Kani-proved IFC)
2. L2: probabilistic, fast (embedding similarity, 100% precision)
3. L3: probabilistic, selective (LLM judge, catches derived info)
