---
name: bench
description: Run Criterion benchmarks
---

Run performance benchmarks using the `benchmarks` crate.

## Usage

- If the user specifies a benchmark name, filter to that benchmark
- Default: run all benchmarks in the `benchmarks` crate

## Commands

All benchmarks:

```bash
cargo bench -p benchmarks
```

Filtered benchmark:

```bash
cargo bench -p benchmarks -- <filter>
```

## Notes

- Criterion outputs comparison against the previous run automatically
- Report the timing results and any regressions
- If no previous baseline exists, note that this is the first run
