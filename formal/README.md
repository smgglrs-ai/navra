# Formal Verification

Formal verification harnesses for navra concurrency properties.

## TLA+ (FlowConcurrency)

Models the flow DAG execution engine to verify that the global
container count never exceeds `max_parallel`, even when main flows
and escalation subflows run concurrently.

### Properties verified

- **ConcurrencyBound**: `running + subflow_running <= max_parallel`
- **PermitConservation**: `permits + running + subflow_running = max_parallel`
- **AllTasksComplete**: all tasks eventually finish (liveness)

### Running

```bash
# Install TLC (TLA+ model checker)
# Option 1: via tla-bin
cargo install tla-bin
# Option 2: download from github.com/tlaplus/tlaplus/releases

# Run model checking (~10s for small model)
cd formal
tlc FlowConcurrency.tla -config FlowConcurrency.cfg

# Larger model (edit .cfg to increase constants)
```

### Interpreting results

If TLC reports "No errors found", the concurrency bound holds for
all reachable states. If it finds a violation, it prints a
counterexample trace showing the sequence of actions that leads
to more than `max_parallel` containers.

## Kani (Rust-level)

Verify Rust code properties for the semaphore and token accounting.

### Properties

- Semaphore permits never go negative
- Token accounting doesn't overflow u32
- Task ID uniqueness in flow_results

### Running

```bash
# Install Kani
cargo install --locked kani-verifier
cargo kani setup

# Run verification
cargo kani --harness verify_token_accounting
```

## Relationship to the OOM crash (2026-05-07)

The 145GB OOM allocation was traced to Ollama's KV cache allocation
for a 35B model, not a navra concurrency bug. The GPU semaphore
(initialized from `max_parallel=2`) correctly limits concurrent
containers. The TLA+ model verifies this design is sound.

The fix is operational: limit `num_ctx` in Ollama config or use
smaller models for specialist agents. The navra throttle works
correctly — the issue is downstream resource management in Ollama.
