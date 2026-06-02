# Semantic Leakage Detection

## Problem

Gateway-level IFC tracks data labels at tool-call boundaries.
When an agent reads tainted content and paraphrases it in a
subsequent tool call, the literal text is different but the
information is the same. Label-based IFC cannot catch this —
the outgoing text doesn't match the tainted value.

Example:
1. Agent reads `file_read("/secrets.env")` → `API_KEY=sk-abc123`
2. Safety pipeline detects secret → labels `Confidentiality::Secret`
3. Session taint rises to Secret
4. Agent calls `http_request(body="the key starts with sk and is 14 chars")`
5. IFC no-write-down blocks ALL writes from tainted sessions (if policy=Deny)
6. But with policy=Approve, human sees innocuous text → approves

This is not a navra-specific limitation. No published IFC system
(FIDES, CaMeL, or navra) can track information flow through LLM
reasoning. NeuroTaint (arXiv:2604.23374) achieves F1=0.928 on
semantic taint detection but runs offline, not in real-time.

## Proposed Solution: SemanticLeakageHook

A new hook in navra's pipeline that compares outgoing content
against tainted values using embedding similarity — catching
paraphrased exfiltration that string-based filters miss.

### Architecture

```
Agent calls write tool (http_request, file_write, git_commit, ...)
    │
    ▼
SemanticLeakageHook::pre_tool_use()
    │
    ├── 1. Extract text content from tool arguments
    │
    ├── 2. Query ValueStore for all values where
    │      confidentiality >= Sensitive
    │
    ├── 3. Embed outgoing text using ONNX embedding model
    │      (same model used for RAG — already loaded)
    │
    ├── 4. Compute cosine similarity against each
    │      tainted value's embedding
    │
    ├── 5. If max_similarity > threshold → BLOCK
    │      "Semantic leakage detected: outgoing content
    │       similar to tainted value {var_id}"
    │
    └── 6. If below threshold → CONTINUE
```

### Components (all exist in navra today)

| Component | Location | Reuse |
|---|---|---|
| ValueStore with labels | `navra-security/src/ifc/value_store.rs` | Query tainted values |
| ONNX embedding model | `navra-model::OnnxBackend` + `ModelTask::Embedding` | Embed outgoing text |
| Cosine similarity | `navra-rag/src/cache.rs::cosine_similarity()` | Compare embeddings |
| Hook trait | `navra-security/src/hooks/mod.rs::Hook` | Implement `pre_tool_use` |
| Write tool detection | `navra-security/src/ifc::is_write_tool()` | Gate the check |

### New code needed

- `navra-security/src/hooks/semantic_leakage.rs` (~150 lines)
- Wire into hook pipeline in `navra-server/src/main.rs`
- Config: `semantic_leakage_threshold = 0.75` in TOML

### What it catches

| Attack | String-based IFC | Semantic leakage hook |
|---|---|---|
| Literal copy of password | Blocked (tainted session) | Blocked (similarity ~1.0) |
| "the password starts with h" | Blocked if policy=Deny | Blocked (moderate similarity) |
| Base64-encoded password | Not detected by content filter | Blocked (decode → embed → high similarity) |
| "send the file content" | Blocked (tainted session) | Blocked (argument text similar to stored content) |
| "password length is 7" | Blocked if policy=Deny | **Maybe not** (low semantic similarity) |
| Timing channel | Not applicable | Not applicable |

### What it cannot catch

- Derived information with no semantic overlap to the original
- Timing/metadata covert channels
- Information encoded in tool selection patterns
- Approval fatigue (human clicks "allow" on blocked request)

### Performance impact

- Embedding inference: ~5-15ms per write tool call (same as NER)
- Cosine similarity: <0.1ms per comparison
- Only runs on write tools (not reads) — reduces frequency
- Only compares against tainted values (not all values) — reduces scope
- Acceptable for gateway use case where tool execution takes 10-500ms

### Threshold tuning

- Too low (0.5): false positives on legitimate text about similar topics
- Too high (0.9): misses paraphrased content
- Recommended default: 0.75 (catches moderate paraphrasing)
- Tunable per permission set in config

### Relationship to existing defenses

This is Layer 3 in navra's defense-in-depth:

| Layer | Mechanism | What it catches | Latency |
|---|---|---|---|
| L1 (Infrastructure) | ACLs, tool scanning, egress filter, manifest pinning | Tool poisoning, supply chain, unauthorized access | <1ms |
| L2 (Data flow) | IFC taint tracking, no-write-down, capability attenuation | Cross-tool exfiltration, privilege escalation | <1us |
| L3 (Semantic) | Embedding similarity against tainted values | Paraphrased exfiltration, encoded content | ~10ms |

L1 and L2 are deterministic (Kani-proved). L3 is probabilistic
(embedding similarity is not exact). The paper should present L3
as "defense-in-depth detection" not "provable security."

### Novel contribution

No published system does gateway-level semantic leakage detection
in real-time. NeuroTaint (F1=0.928) runs offline. FIDES and CaMeL
don't address semantic propagation. This would be a fourth paper
contribution alongside:
1. Gateway-enforced IFC (L2)
2. Capability delegation with attenuation
3. Hash-chained audit trail
4. **Semantic leakage detection via embedding similarity (L3)**
