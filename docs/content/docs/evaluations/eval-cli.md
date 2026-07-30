+++
title = "Eval CLI Reference"
weight = 5

template = "docs/page.html"
[extra]
toc = true
+++

The `navra eval` command runs adversarial security evaluations
against navra's defense layers and generates comparison reports.

## Subcommands

### `navra eval agent-dojo`

Runs the AgentDojo IFC defense benchmark. This tests navra's
information flow control against read→write attack patterns
where an agent reads untrusted data and attempts to exfiltrate
it via write tools.

Requires the `agentdojo` Python package (`pip install agentdojo`)
and a running navra instance or compatible LLM endpoint.

```bash
# Default: 5 tasks, workspace suite, both defenses
navra eval agent-dojo

# Custom run
navra eval agent-dojo \
  --tasks 20 \
  --suite workspace \
  --model qwen3:8b \
  --defense ifc \
  --attack important_instructions \
  --output results.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--tasks` | `5` | Max user tasks to evaluate |
| `--suite` | `workspace` | AgentDojo task suite |
| `-m, --model` | `claude-sonnet-4-6@default` | LLM model identifier |
| `--defense` | `both` | Defense to test: `none`, `ifc`, or `both` |
| `--attack` | `important_instructions` | Attack type |
| `-o, --output` | `eval_agentdojo_{suite}_{tasks}tasks.json` | Output JSON path |
| `--python` | `python3` | Python interpreter |

When `--defense both` is used, the benchmark runs twice (with and
without IFC) and writes both results into the output file for
side-by-side comparison.

Output includes per-defense security rate, utility rate, and
per-task details in the standard `EvalResults` JSON format.

### `navra eval mcp-tox`

Runs the MCPTox tool poisoning detection benchmark against
navra's `ToolScanner`. This evaluates whether navra detects
malicious tool definitions (prompt injection in descriptions,
payload poisoning, hidden instructions) at registration time.

Requires the MCPTox dataset:

```bash
git clone https://github.com/zhiqiangwang4/MCPTox-Benchmark.git /tmp/mcptox
navra eval mcp-tox
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dataset` | `/tmp/mcptox` | Path to cloned MCPTox dataset |
| `-o, --output` | `eval_mcptox_results.json` | Output JSON path |

The benchmark:

1. Loads poisoned tool definitions from `pure_tool.json`
2. Scans each with navra's `ToolScanner` (same code that runs at
   startup against upstream MCP servers)
3. Loads clean tool definitions from `response_all.json`
4. Measures false positive rate on clean tools
5. Reports detection rate, false positive rate, per-category
   breakdown, and lists missed tools

Output includes per-tool scan results with finding categories
and severity levels.

### `navra eval report`

Generates a markdown comparison table from one or more eval
result JSON files. Use this to compare runs across different
models, defenses, or configurations.

```bash
# Compare two runs
navra eval report baseline.json with_ifc.json -o comparison.md

# Multiple files, stdout
navra eval report run1.json run2.json run3.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `files` | (required) | One or more result JSON files |
| `-o, --output` | stdout | Output markdown file |

The report reads the `EvalResults` envelope from each file and
renders a side-by-side table with totals, pass/fail counts,
rates, and any extra metrics (security rate, utility rate,
detection rate, false positive rate).

## Output Format

All subcommands produce JSON in the `EvalResults` envelope:

```json
{
  "eval_type": "agentdojo" | "mcptox",
  "timestamp": "2026-07-30T14:00:00Z",
  "summary": {
    "total": 100,
    "passed": 95,
    "failed": 5,
    "rate": 0.95
  },
  "cases": [...]
}
```

The `summary.extra` field carries eval-specific metrics:

- **AgentDojo**: `defense`, `model`, `security_rate`, `utility_rate`
- **MCPTox**: `detection_rate`, `false_positive_rate`,
  `false_positives`, `clean_tools_total`, `categories`

## Relationship to Other Evaluations

| Evaluation | What it tests | How to run |
|------------|---------------|------------|
| **`navra eval agent-dojo`** | IFC defense against read→write exfiltration | This page |
| **`navra eval mcp-tox`** | Tool poisoning detection at registration | This page |
| [IFC Adversarial Corpus](@/docs/evaluations/ifc-benchmark.md) | IFC label enforcement (261 vectors, unit-level) | `cargo test -p navra-auth --test ifc_benchmark` |
| [ASSERT Evaluation](@/docs/evaluations/assert-evaluation.md) | Policy compliance via LLM-as-judge | `just assert-eval` |
| [ADR-Bench Mapping](@/docs/evaluations/adr-bench-mapping.md) | Coverage analysis against 17 attack techniques | Documentation only |
