# Review and improvement flows

The framework reviews and improves projects through its own gateway
using DAG-based multi-agent flows. Four flow templates are available:

| Flow | Persona selection | Use case |
|------|------------------|----------|
| `comprehensive-review.yaml` | Hardcoded (5 personas) | Baseline code review |
| `review.yaml` | Dynamic (scout classifies → planner picks) | Domain-agnostic review |
| `self-improve.yaml` | Hardcoded | Code improvement cycle |
| `improve.yaml` | Dynamic | Domain-agnostic improvement |

### Running

```bash
# Start the server
navra serve

# Run a review via MCP (from any MCP client)
flow_start(flow_name="review", prompt="Review the project",
  parameters={"target_dir": "/path/to/project"})

# Or use the hardcoded variant
flow_start(flow_name="comprehensive-review", ...)

# Improvement cycle (creates git worktree for isolation)
navra improve --target . --cycles 3 --branch self-improve
```

### Comparative results (2026-05-07)

| Metric | Hardcoded | Dynamic | Ratio |
|--------|-----------|---------|-------|
| Wall clock | 32 min | 21 min | 0.66x |
| Total tokens | 3.77M | 1.78M | 0.47x |
| Specialists | 23 | 14 | — |
| Precision (real findings) | 37.5% | 62.5% | 1.67x |
| False positive rate | 25% | 12.5% | 0.50x |
| Real findings / M tokens | 0.80 | 2.81 | 3.5x |
| Cost per real finding | 1.26M tok | 0.36M tok | 3.5x cheaper |

Dynamic persona selection dominates: better quality at lower cost.
The planner picks personas that match the project domain rather
than spreading evenly across hardcoded categories.

### Audit metrics (current state)

**Captured in audit.db:**
- `flow_results`: per-task output, specialist, model, tokens
  (cumulative), started_at, completed_at
- `flow_metadata`: YAML content, parameters, flow-level timing
- `audit_runs`: per-agent run metadata
- `audit_tool_calls`: schema exists but **not populated** for
  flow agents (Phase 12a)
- `audit_model_calls`: schema exists but **not populated** for
  flow agents (Phase 12a)

**Known metrics gaps** (see Phase 12):
- Per-task duration always 0 (started_at == completed_at)
- Per-task iteration count always NULL
- Per-task tokens are cumulative, not per-agent
- Model name stored as "auto" instead of resolved name
- No GPU utilization recording

---
