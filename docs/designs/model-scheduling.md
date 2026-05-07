# Model-Aware Task Scheduling and IFC-Safe Data Flow

## Problem

Three interconnected issues in flow execution:

1. **Scheduling inefficiency**: The DAG executor spawns agents in
   dependency order, not model order. Each model load/unload takes
   10-30s. With 15-20 specialists, unnecessary model switches
   dominate execution time.

2. **KV cache data leak**: Ollama's KV cache persists between
   requests on the same loaded model. A Sensitive-tainted agent's
   context may influence a Public agent's responses.

3. **IFC bypass in output propagation**: Specialist outputs flow
   to the synthesizer and leader via inline injection and
   `flow_result` — both paths bypass IFC enforcement entirely.
   The blackboard enforces taint-on-read, but the flow engine
   doesn't use it for output propagation.

## Design constraints

1. **DAG dependencies must be satisfied** — a task can only run
   after its dependencies complete
2. **max_parallel limits concurrency** — at most N agents run
   simultaneously (GPU semaphore)
3. **IFC taint must not leak** — a Sensitive-tainted agent's
   context must not reach a Public agent via shared model state
4. **Efficiency matters** — minimize model load/unload cycles
5. **Agents need communication channels** — if KV cache is erased,
   agents must have other ways to share findings

## KV Cache security analysis

### Threat model

Ollama loads a model and maintains a KV cache across requests.
When two agents use the same model sequentially:

- **Direct replay**: No — each request starts a new conversation.
  The KV cache is per-conversation in Ollama's server mode.
- **Model weight contamination**: No — weights are read-only.
- **Residual activation patterns**: Possible in theory but not
  demonstrated for Ollama's architecture.
- **Context window overflow**: If the KV cache isn't cleared between
  conversations, previous context could appear in a new session.

### Risk assessment

With Ollama's `--parallel N` flag, each request slot has an
independent KV cache. When the container agent connects to Ollama
via `/v1/chat/completions`, it gets a fresh conversation context.
The risk is LOW for chat-mode Ollama but MEDIUM for raw `/api/generate`
where context can persist via the `context` field.

### Mitigation

1. **Always use chat completions API** (current behavior) — each
   request is a fresh conversation
2. **Set `keep_alive: 0`** on model unload between IFC boundary
   crossings (when consecutive agents have different taint levels)
3. **Use `--parallel N`** on the shared model server — independent
   KV caches per slot

## IFC enforcement audit (current state)

| Data path | IFC enforced? | Mechanism | Risk |
|-----------|---------------|-----------|------|
| Blackboard read | ✅ | taint-on-read (lattice join) | Safe |
| Blackboard publish | ⚠️ | Entry carries author's label, but no write-up check | Medium |
| Mailbox post | ✅ | Bell-LaPadula no-write-down | Safe |
| flow_result tool | ❌ | No label check, no taint propagation | **HIGH** |
| Inline output injection | ❌ | Specialist outputs injected as raw text | **HIGH** |
| Leader reads team_result | ❌ | No label check | **HIGH** |

### The synthesizer problem

The synthesizer reads ALL specialist outputs — including those
from security_sentinel agents that may have read PII or secrets.
The synthesizer's report is then returned to the caller, potentially
crossing an IFC boundary.

Current code (flow_tools.rs line 839):
```rust
// Inject specialist output directly — NO IFC CHECK
message.push_str(&format!("\n## {dep_id}\n{output}\n"));
```

### Fix: route outputs through blackboard

Instead of inline injection, specialist outputs should be
auto-published to the blackboard with the specialist's taint label.
The synthesizer reads via blackboard (taint-on-read), which
propagates the label. If any specialist was PII-tainted, the
synthesizer's report inherits that taint, and the gateway's IFC
policy decides whether the caller can receive it.

```
Specialist (taint: PII) → blackboard.publish("findings/sec-01",
    output, label=Pii) → synthesizer reads → taint absorbs Pii
    → synthesizer output labeled Pii → gateway checks caller's
    clearance before returning
```

This makes the leader/synthesizer subject to the same IFC rules
as every other agent. No special privileges.

### Acceptable read patterns

| Reader | Reads from | Acceptable? | Why |
|--------|-----------|-------------|-----|
| Leader | All specialist outputs | YES if taint propagates | Leader's report inherits max taint |
| Synthesizer | All specialist outputs | YES if taint propagates | Same — report carries taint |
| Specialist A | Specialist B output | Only via blackboard | Taint-on-read enforced |
| External caller | Synthesizer report | Only if clearance >= taint | Gateway IFC check |

The key insight: **it's acceptable for the leader/synthesizer to
read everything, as long as their output inherits the taint**. The
restriction is on who can read the synthesizer's report downstream.

## Communication channels vs KV Cache

| Channel | Persistence | IFC-gated | Capacity | Latency |
|---------|-------------|-----------|----------|---------|
| KV Cache | Implicit, ephemeral | NO | Model context window | 0 |
| Blackboard | Explicit, per-flow | YES (taint-on-read) | Configurable (256 entries) | ~1ms |
| Mailbox | Explicit, per-agent | YES (no-write-down) | Configurable (64 msgs) | ~1ms |
| Memory (KnowledgeStore) | Persistent, cross-flow | YES (PII filter) | Unlimited (SQLite) | ~5ms |
| flow:// resources | Persistent, per-flow | YES | Audit.db | ~10ms |

**Conclusion**: The explicit channels (blackboard, mailbox, memory)
provide equivalent information sharing with IFC enforcement. KV Cache
erasure between agents is the safe default. The ~1ms latency of
blackboard/mailbox is negligible vs the 10-30s model load time.

## Nudging agents to use communication channels

### Current behavior

Specialists receive their mandate and prior dependency outputs as
inline text in their system prompt. They have tools (`team_bb_publish`,
`team_bb_read`, `flow_result`) but nothing tells them to use them.

### Proposed changes

1. **Auto-publish to blackboard**: When a specialist completes, the
   flow engine auto-publishes a summary of its output to the
   blackboard under `findings/{task_id}`. Downstream agents can
   read these explicitly.

2. **System prompt injection**: Add to every specialist's system
   prompt: "Previous specialists published findings to the
   blackboard. Use team_bb_read to check for relevant context
   before starting your analysis."

3. **Memory integration**: After each flow completes, distill
   specialist findings into the KnowledgeStore with proper PII
   filtering. Future flows benefit from past findings.

4. **Don't over-harness**: For ≥20B models, a brief mention of
   blackboard availability is sufficient. For ≤10B models, more
   explicit instructions are needed but we accept lower quality.

## Model-aware scheduling algorithm

### Input

- DAG: tasks with dependencies, each assigned a model (or "auto")
- Model cards: available models with load times and memory requirements
- max_parallel: concurrency limit
- IFC labels: per-task taint levels

### Algorithm

```
1. Resolve "auto" models for all tasks (select_model_for_task)

2. Topological sort tasks by dependency depth

3. Within each dependency level, group tasks by model:
   level_0: [scout (gemma4:e4b)]
   level_1: [planner (gemma4:26b)]
   level_2: [arch-01 (qwen3.6:35b), arch-02 (qwen3.6:35b),
             sec-01 (gemma4:26b), sec-02 (gemma4:26b),
             code-01 (qwen3.6:35b)]

4. Within each level, sort groups by model to minimize switches:
   level_2 sorted: [qwen3.6:35b × 3, gemma4:26b × 2]

5. Spawn in model-grouped order within max_parallel:
   - Batch 1: arch-01 (qwen3.6:35b), arch-02 (qwen3.6:35b)
   - Batch 2: code-01 (qwen3.6:35b), sec-01 (gemma4:26b)
     ↑ model switch here — if IFC labels differ, erase KV cache
   - Batch 3: sec-02 (gemma4:26b)

6. Between batches that cross IFC boundaries:
   - Call Ollama `/api/generate` with `keep_alive: "0"` to unload
   - Or rely on chat completions mode (per-request KV cache)
```

### IFC-aware cache decisions

```
For each consecutive pair of agents on the same model:
  if agent_A.taint_level > agent_B.taint_level:
    # Sensitive → Public: MUST erase (Bell-LaPadula)
    erase_kv_cache()
  elif agent_A.taint_level == agent_B.taint_level:
    # Same level: safe to keep (no information flow violation)
    keep_model_loaded()
  else:
    # Public → Sensitive: safe (reading up is allowed)
    keep_model_loaded()
```

## Implementation plan

### Step 1: Route outputs through blackboard (HIGH — IFC fix)

**Files**: `smgglrs-server/src/flow_tools.rs`

Replace inline output injection with blackboard-mediated flow:

1. After each specialist completes, auto-publish its output to
   the team blackboard under `findings/{task_id}` with the
   specialist's accumulated taint label.

2. For the synthesizer (and any task with >5 dependencies),
   instead of injecting outputs inline or pointing to flow_result,
   tell the agent to read from the blackboard via `team_bb_read`.
   The taint-on-read mechanism propagates IFC labels automatically.

3. Add taint label to `flow_result` tool responses — when
   `flow_result` returns specialist output, tag the response
   with the specialist's taint from the session's context_label.

**Effort**: 2-3 days. **Priority**: HIGH (IFC bypass).

### Step 2: Model grouping in ready queue (1 day)

**File**: `smgglrs-server/src/flow_tools.rs`

In `run_dag_execution`, after `get_ready_tasks()` and before
`truncate(max_parallel)`:

```rust
// Sort ready tasks by resolved model to minimize switches.
// All tasks in `ready` have satisfied dependencies — ordering
// within the ready set is free.
ready.sort_by_key(|t| t.model.clone().unwrap_or_default());
```

This one-line change improves model locality without breaking
DAG semantics.

### Step 3: IFC-aware cache policy (1 day)

Between consecutive batches, check if the taint level changes:

```rust
if prev_batch_max_taint > next_batch_min_clearance {
    // Sensitive → Public transition: must erase
    ollama_unload_model(&model_name).await;
}
```

Call Ollama's `/api/generate` with `keep_alive: "0"` to force
model unload. Only needed at IFC boundary crossings.

### Step 4: Agent nudging (1 day)

Add to specialist system prompts:
- "Your findings will be published to the team blackboard.
  Check team_bb_read for context from other specialists."

Auto-inject this when the flow has a blackboard configured.
Don't over-harness — one sentence is sufficient for ≥20B models.

## Metrics for paper

- Model load/unload count per flow (before vs after scheduling)
- Wall clock time reduction
- Token efficiency (should be unchanged — same work, less waiting)
- Finding quality (should be unchanged — same agents, same mandates)
