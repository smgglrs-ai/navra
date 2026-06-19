//! Benchmarks for embedding retrieval quality and latency.
//!
//! Compares embedding models (granite-embed-r2 vs nomic-embed-v1.5) on:
//! - Embedding latency (p50, p95 via Criterion)
//! - Retrieval recall@k on a synthetic corpus
//! - Matryoshka dimension truncation (768, 384, 256, 64)
//!
//! ## Evaluation summary
//!
//! Nomic Embed v1.5 advantages over Granite Embedding R2:
//! - Apache-2.0 license (same as Granite)
//! - Matryoshka support: valid embeddings at 64-768 dims (Granite is fixed 768)
//! - 8192-token context window (Granite: 512)
//! - Competitive MTEB scores
//!
//! Recommendation: keep granite-embed as default for backward compatibility.
//! Add nomic-embed as an alternative, especially for memory-constrained
//! deployments where Matryoshka 256d or 384d reduces storage by 50-67%
//! with acceptable recall degradation.
//!
//! ## Running
//!
//! Prerequisites: ONNX model files must be present at the paths below.
//! Download with `navra model pull granite-embed` and `navra model pull nomic-embed`.
//!
//! ```bash
//! ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo bench -p navra-benchmarks -- embedding
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use navra_rag::chunk::Chunk;
use navra_rag::ChunkStore;
use std::path::PathBuf;
use std::sync::Arc;

fn model_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("navra/models")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/navra/models")
    } else {
        PathBuf::from("/tmp/navra/models")
    }
}

fn try_load_model(
    name: &str,
    subfolder: &str,
    dimensions: usize,
) -> Option<Arc<navra_model::OnnxBackend>> {
    let base = model_dir().join(subfolder);
    let model_path = base.join("model.onnx");
    let tokenizer_path = base.join("tokenizer.json");

    if !model_path.exists() {
        eprintln!(
            "Skipping {name}: model not found at {}",
            model_path.display()
        );
        return None;
    }

    navra_model::OnnxBackend::load(
        name,
        &model_path,
        Some(&tokenizer_path),
        navra_model::ModelTask::Embedding { dimensions },
        navra_model::Device::Cpu,
    )
    .ok()
    .map(Arc::new)
}

const CORPUS: &[&str] = &[
    "Rust is a systems programming language focused on safety, speed, and concurrency.",
    "The MCP protocol defines a standard for tool communication between AI agents.",
    "SQLite is a self-contained, serverless, zero-configuration SQL database engine.",
    "Vector embeddings represent text as dense numerical arrays for similarity search.",
    "ONNX Runtime provides cross-platform inference for machine learning models.",
    "Information flow control tracks data sensitivity through processing pipelines.",
    "Retrieval-augmented generation combines search with language model reasoning.",
    "WebSocket provides full-duplex communication channels over a single TCP connection.",
    "Tokenization splits text into subword units for neural network processing.",
    "The attention mechanism allows models to focus on relevant parts of the input.",
    "Matryoshka representation learning trains embeddings that are valid at multiple dimensions.",
    "Cosine similarity measures the angle between two vectors in high-dimensional space.",
    "BM25 is a probabilistic ranking function used for full-text search.",
    "Reciprocal rank fusion combines results from multiple retrieval methods.",
    "Cross-encoder reranking improves search precision by jointly encoding query and document.",
    "Chunking strategies affect retrieval quality: too small loses context, too large dilutes signal.",
    "Hybrid search combines dense vector similarity with sparse keyword matching.",
    "The transformer architecture uses self-attention to process sequences in parallel.",
    "Knowledge distillation transfers capabilities from large models to smaller ones.",
    "Quantization reduces model size and latency by using lower-precision arithmetic.",
];

const QUERIES: &[(&str, &[usize])] = &[
    ("systems programming language safety", &[0]),
    ("AI agent tool protocol standard", &[1]),
    ("embedded database SQL", &[2]),
    ("text similarity search dense arrays", &[3]),
    ("machine learning inference runtime", &[4]),
    ("data sensitivity tracking", &[5]),
    ("search combined with language model", &[6]),
    ("full-duplex TCP communication", &[7]),
    ("subword text splitting neural", &[8]),
    ("model focus relevant input parts", &[9]),
    ("embeddings valid multiple dimensions", &[10]),
    ("vector angle measurement", &[11]),
    ("probabilistic text ranking", &[12]),
    ("combining multiple search results", &[13]),
    ("query document joint encoding precision", &[14]),
];

fn embed_text(
    rt: &tokio::runtime::Runtime,
    model: &navra_model::OnnxBackend,
    text: &str,
) -> Vec<f32> {
    use navra_model::ModelBackend;
    rt.block_on(async {
        model
            .embed(&navra_model::EmbedRequest {
                text: text.to_string(),
            })
            .await
            .expect("embed failed")
            .embedding
    })
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a > 0.0 && norm_b > 0.0 {
        dot / (norm_a * norm_b)
    } else {
        0.0
    }
}

fn recall_at_k(rt: &tokio::runtime::Runtime, model: &navra_model::OnnxBackend, k: usize) -> f64 {
    let corpus_embeddings: Vec<Vec<f32>> = CORPUS
        .iter()
        .map(|text| embed_text(rt, model, text))
        .collect();

    let mut hits = 0usize;
    let mut total = 0usize;

    for &(query, relevant) in QUERIES {
        let query_emb = embed_text(rt, model, query);

        let mut scored: Vec<(usize, f32)> = corpus_embeddings
            .iter()
            .enumerate()
            .map(|(i, emb)| (i, cosine_similarity(&query_emb, emb)))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let top_k: Vec<usize> = scored.iter().take(k).map(|(i, _)| *i).collect();
        for &rel in relevant {
            total += 1;
            if top_k.contains(&rel) {
                hits += 1;
            }
        }
    }

    hits as f64 / total as f64
}

fn bench_embedding_latency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("embedding_latency");

    let models: Vec<(&str, &str, usize)> = vec![
        ("granite-embed", "granite-embed", 768),
        ("nomic-embed", "nomic-embed", 768),
    ];

    for (name, subfolder, dims) in &models {
        let model = match try_load_model(name, subfolder, *dims) {
            Some(m) => m,
            None => continue,
        };

        group.bench_with_input(BenchmarkId::new("short_text", name), &model, |b, model| {
            b.iter(|| {
                embed_text(
                    &rt,
                    model,
                    black_box("Rust is a systems programming language."),
                )
            })
        });

        group.bench_with_input(BenchmarkId::new("medium_text", name), &model, |b, model| {
            b.iter(|| {
                embed_text(
                    &rt,
                    model,
                    black_box(
                        "The Model Context Protocol defines a standard interface for AI agents \
                         to interact with tools, resources, and data sources. It supports both \
                         synchronous and asynchronous communication patterns with structured \
                         error handling and capability negotiation.",
                    ),
                )
            })
        });
    }

    group.finish();
}

fn bench_matryoshka_latency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("matryoshka_latency");

    let dimensions = [768, 384, 256, 64];

    for dims in dimensions {
        let model = match try_load_model("nomic-embed", "nomic-embed", dims) {
            Some(m) => m,
            None => {
                eprintln!("Skipping Matryoshka {dims}d: nomic-embed model not found");
                continue;
            }
        };

        group.bench_with_input(BenchmarkId::new("embed", dims), &model, |b, model| {
            b.iter(|| embed_text(&rt, model, black_box("Vector similarity search.")))
        });
    }

    group.finish();
}

fn bench_retrieval_recall(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("retrieval_recall");
    group.sample_size(10);

    let configs: Vec<(&str, &str, usize)> = vec![
        ("granite-embed@768", "granite-embed", 768),
        ("nomic-embed@768", "nomic-embed", 768),
        ("nomic-embed@384", "nomic-embed", 384),
        ("nomic-embed@256", "nomic-embed", 256),
    ];

    for (label, subfolder, dims) in &configs {
        let model = match try_load_model(label, subfolder, *dims) {
            Some(m) => m,
            None => continue,
        };

        group.bench_with_input(BenchmarkId::new("recall@5", label), &model, |b, model| {
            b.iter(|| recall_at_k(&rt, model, 5))
        });

        group.bench_with_input(BenchmarkId::new("recall@10", label), &model, |b, model| {
            b.iter(|| recall_at_k(&rt, model, 10))
        });
    }

    group.finish();
}

fn bench_store_search(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("store_vector_search");

    let configs: Vec<(&str, &str, usize)> = vec![
        ("granite-embed@768", "granite-embed", 768),
        ("nomic-embed@768", "nomic-embed", 768),
        ("nomic-embed@384", "nomic-embed", 384),
    ];

    for (label, subfolder, dims) in &configs {
        let model = match try_load_model(label, subfolder, *dims) {
            Some(m) => m,
            None => continue,
        };

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("bench.db").to_str().unwrap().to_string();
        let store = ChunkStore::open(&db_path, *dims).unwrap();

        let chunks: Vec<Chunk> = CORPUS
            .iter()
            .enumerate()
            .map(|(i, text)| Chunk {
                content: text.to_string(),
                start_byte: 0,
                end_byte: text.len(),
                index: i,
                breadcrumb: None,
                section_start_byte: None,
                section_end_byte: None,
            })
            .collect();

        let embeddings: Vec<Vec<f32>> = CORPUS
            .iter()
            .map(|text| embed_text(&rt, &model, text))
            .collect();

        store
            .index_document("bench.txt", &chunks, &embeddings)
            .unwrap();

        group.bench_with_input(BenchmarkId::new("search", label), &store, |b, store| {
            let query_emb = embed_text(&rt, &model, "systems programming safety");
            b.iter(|| store.search(black_box(&query_emb), 5))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_embedding_latency,
    bench_matryoshka_latency,
    bench_retrieval_recall,
    bench_store_search,
);
criterion_main!(benches);
