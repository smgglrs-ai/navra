---
name: bench
description: Run Criterion benchmarks with ONNX Runtime environment variables
---

Run performance benchmarks using the `benchmarks` crate.

## Usage

- If the user specifies a benchmark name, filter to that benchmark
- Default: run all benchmarks in the `benchmarks` crate

## Commands

All benchmarks:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo bench -p benchmarks
```

Filtered benchmark:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo bench -p benchmarks -- <filter>
```

## Notes

- Criterion outputs comparison against the previous run automatically
- Report the timing results and any regressions
- If no previous baseline exists, note that this is the first run
