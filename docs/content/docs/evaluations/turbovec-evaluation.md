+++
title = "TurboVec Evaluation for navra-rag"
weight = 10


template = "docs/page.html"
[extra]
toc = true
+++


Evaluation of TurboVec as a potential replacement for sqlite-vec in
the navra-rag vector store.

## Verdict: Reject (sqlite-vec quantization is sufficient)

TurboVec is real, well-maintained code (12K stars, MIT, Rust crate
v0.9.0) with strong quantization performance. However, replacing
sqlite-vec with TurboVec would regress navra-rag's core capability:
hybrid search combining FTS5 + vector + rerank via RRF fusion.

## TurboVec Assessment

- **Repository**: github.com/RyanCodrai/turbovec (12K stars)
- **Crate**: turbovec 0.9.0 on crates.io
- **Quantization**: 2-bit and 4-bit via TurboQuant algorithm
- **API**: `IdMapIndex` with u64 IDs, SIMD search, O(1) deletion
- **Persistence**: Custom .tv/.tvim format (not SQLite)

### Strengths
- Pure Rust, no C dependencies
- 2-4 bit quantization reduces memory 8-16x vs f32
- SIMD-accelerated search (AVX2/NEON)
- Clean API for pure vector workloads

### Fundamental Mismatch
- **No SQL integration**: TurboVec is a standalone index. navra-rag's
  `ChunkStore` uses SQLite for metadata (paths, tags, doc_type, FTS5),
  and sqlite-vec for vector search, unified in a single database file.
  Replacing sqlite-vec with TurboVec would require:
  - Maintaining two storage backends (SQLite for metadata + TurboVec
    for vectors)
  - Reimplementing hybrid search (FTS5 + vector RRF fusion)
  - Losing SQL-based metadata filtering on vector queries
  - Separate persistence lifecycle (WAL journal + .tvim files)
- **No FTS**: TurboVec is pure ANN. navra-rag's hybrid search
  combines BM25 keyword ranking with vector similarity via Reciprocal
  Rank Fusion. This is the primary retrieval path.

## Better Alternatives Within sqlite-vec

sqlite-vec (v0.1.6-alpha.2, our current dependency) already supports:

1. **Int8 quantization**: `vec_int8()` column type with L2 distance.
   8x memory reduction vs f32. Available now.
2. **Binary quantization**: `vec_quantize_binary()` scalar function.
   32x memory reduction. Hamming distance search. Available now.
3. **Reranking pattern**: Binary search for candidates → f32 rerank
   for precision. Documented at alexgarcia.xyz/sqlite-vec/guides/binary-quant.html.

### sqlite-vector (alternative)

SQLite AI's sqlite-vector project (966 stars) integrates TurboQuant
natively (`qtype=TURBO`, 2/3/4-bit) within the SQLite virtual table
framework. Claims 17x faster than sqlite-vec with quantization +
preload, with perfect recall. However:
- Different project, different maintainer (Marco Bambini / SQLite AI)
- Smaller community than sqlite-vec
- Would require swapping the SQLite extension dependency

## Recommendation

1. **Immediate**: Use sqlite-vec's built-in `vec_int8()` for 8x
   memory reduction with no API changes. Just change the column
   type in `ChunkStore::open()`.
2. **Future**: When sqlite-vec reaches stable, evaluate binary
   quantization with reranking for 32x reduction.
3. **Skip TurboVec**: The architectural mismatch (pure vector vs
   SQL-integrated) makes it a poor fit for navra-rag's hybrid
   search design.

## References

- TurboVec: https://github.com/RyanCodrai/turbovec
- sqlite-vec: https://github.com/asg017/sqlite-vec
- sqlite-vec binary quantization: https://alexgarcia.xyz/sqlite-vec/guides/binary-quant.html
- sqlite-vector (TurboQuant): https://github.com/sqliteai/sqlite-vector
- State of Vector Search in SQLite: https://marcobambini.substack.com/p/the-state-of-vector-search-in-sqlite
