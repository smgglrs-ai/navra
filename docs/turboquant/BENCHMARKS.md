# Multi-Turn Tool Calling Benchmark Methodology

## Objective

Measure how KV cache quantization affects multi-turn tool calling
accuracy in llama.cpp. Produce evidence for upstream contribution.

## Test Matrix

### KV Cache Configurations

Symmetric (K and V same type):

| Config | K Type | V Type | Bits/Value |
|--------|--------|--------|-----------|
| baseline | f16 | f16 | 16 |
| q8-sym | q8_0 | q8_0 | 8.5 |
| q4-sym | q4_0 | q4_0 | 4 |
| turbo4-sym | turbo4 | turbo4 | 4.25 |
| turbo3-sym | turbo3 | turbo3 | 3.125 |
| turbo2-sym | turbo2 | turbo2 | 2.125 |

Asymmetric (K at higher precision, V compressed):

| Config | K Type | V Type | Rationale |
|--------|--------|--------|-----------|
| q8k-turbo3v | q8_0 | turbo3 | K controls softmax routing |
| q8k-turbo2v | q8_0 | turbo2 | Maximum V compression |
| q8k-turbo4v | q8_0 | turbo4 | Mild V compression |
| q8k-q4v | q8_0 | q4_0 | Upstream baseline comparison |

Layer-adaptive modes (adaptive-turboquant fork only):

| Config | Mode | Description |
|--------|------|-------------|
| la-1 | TURBO_LAYER_ADAPTIVE=1 | K+V q8_0 first4+last4 |
| la-12 | TURBO_LAYER_ADAPTIVE=12 | V-only q8_0 first4+last4 |
| la-15 | TURBO_LAYER_ADAPTIVE=15 | K last8 q8_0 + V boundary |

### Models

Selected for strong tool calling support with chat templates that
handle tool calls natively:

| Model | Parameters | Why |
|-------|-----------|-----|
| Qwen3-27B (Q6_K) | 27B | Best tool calling in class, widely used |
| Llama-3.3-70B (Q4_K_M) | 70B | Reference model, fits on 5090 at Q4 |
| Mistral-Nemo-12B (Q8_0) | 12B | Smaller model, faster iteration |

### Tool Calling Scenarios

**Scenario 1: Single tool call per turn (1-5 turns)**
```
Turn 1: User asks question -> Model calls tool_A -> Result -> Model responds
Turn 2: User asks follow-up -> Model calls tool_B -> Result -> Model responds
...
Turn 5: User asks final question -> Model calls tool_E -> Result -> Final response
```

**Scenario 2: Parallel tool calls (1 turn, multiple tools)**
```
Turn 1: User asks complex question -> Model calls tool_A + tool_B + tool_C
```

**Scenario 3: Chained tool calls (tool result triggers next tool)**
```
Turn 1: User asks -> Model calls tool_A -> Result -> Model calls tool_B -> Result -> Response
```

### Tools Definition

Three tools with varying complexity:

```json
[
  {
    "name": "get_weather",
    "description": "Get current weather for a city",
    "parameters": {
      "type": "object",
      "properties": {
        "city": {"type": "string"},
        "units": {"type": "string", "enum": ["celsius", "fahrenheit"]}
      },
      "required": ["city", "units"]
    }
  },
  {
    "name": "search_database",
    "description": "Search a database by query and filters",
    "parameters": {
      "type": "object",
      "properties": {
        "query": {"type": "string"},
        "table": {"type": "string"},
        "limit": {"type": "integer"},
        "order_by": {"type": "string"}
      },
      "required": ["query", "table", "limit", "order_by"]
    }
  },
  {
    "name": "send_notification",
    "description": "Send a notification to a user",
    "parameters": {
      "type": "object",
      "properties": {
        "user_id": {"type": "string"},
        "message": {"type": "string"},
        "priority": {"type": "string", "enum": ["low", "medium", "high"]},
        "channel": {"type": "string", "enum": ["email", "sms", "push"]}
      },
      "required": ["user_id", "message", "priority", "channel"]
    }
  }
]
```

All parameters are **required** (not optional) to avoid the known
llama.cpp issue #20164 where optional parameters cause tool calling
failures under long context.

## Metrics

For each configuration x model x scenario, measure:

1. **Tool call success rate**: % of turns where the model produces a
   valid tool call with correct JSON syntax
2. **Argument accuracy**: % of tool call arguments that match expected
   types and constraints (enum values, integer types)
3. **Tool name accuracy**: % of turns where the model calls the
   correct tool (not hallucinating tool names)
4. **Degradation curve**: Success rate plotted per turn number
   (turn 1 vs turn 2 vs turn 3 vs turn 4 vs turn 5)
5. **Perplexity delta**: PPL difference from f16 baseline (existing
   TurboQuant benchmarks cover this; we add tool-calling-specific data)

## Execution

Each test:
- 10 runs per configuration (for statistical significance)
- Temperature 0.0 (deterministic)
- Context cleared between test cases (not between turns within a case)
- Server started fresh for each KV config change

### Infrastructure

```
llama-server \
  --model <model.gguf> \
  --ctx-size 8192 \
  --cache-type-k <k_type> \
  --cache-type-v <v_type> \
  --host 127.0.0.1 \
  --port 8080
```

Test harness sends OpenAI-compatible chat completions with tools via
`/v1/chat/completions`.

## Expected Outcomes

Based on the root cause analysis, we predict:

1. f16 and q8_0 symmetric: 100% success across all turns
2. q4_0 symmetric: degradation starting at turn 2-3
3. turbo3/turbo2 symmetric: degradation at turn 1-2 (more aggressive quant)
4. q8_0 K + turbo3 V (asymmetric): success rate close to q8_0 symmetric
   (K precision preserved, V quantization is more forgiving)
5. Layer-adaptive modes: improvement over symmetric turbo3, proportional
   to how many boundary layers are promoted

If prediction 4 holds, the fix is simple: recommend asymmetric K/V as
the default for tool-calling workloads. If it doesn't, the tool-call
anchoring fix (PR 2) becomes necessary.

## Output

- Raw data as JSON (per-run results)
- Summary table for upstream discussion post
- Degradation curve plots (success rate vs turn number per config)
