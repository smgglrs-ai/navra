//! Benchmark: TemporalTree vs KnowledgeStore
//!
//! Compares write throughput, temporal queries, and retrieval for
//! flat KnowledgeStore vs hierarchical TemporalTree.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use navra_memory::temporal::{TemporalTree, TreeType};
use navra_memory::{KnowledgeStore, MemoryEntry, MemoryType};

fn make_entry(i: usize, ts: i64) -> MemoryEntry {
    MemoryEntry {
        id: format!("entry-{i}"),
        memory_type: MemoryType::Fact,
        title: format!("Fact about topic {}", i % 50),
        content: format!(
            "The system discovered that component {} behaves differently \
             under load condition {}. This was observed at timestamp {}.",
            i % 20,
            i % 5,
            ts
        ),
        tags: vec![format!("topic-{}", i % 50)],
        created_at: ts,
        updated_at: Some(ts),
    }
}

fn bench_write_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_throughput");

    for count in [100, 500, 1000] {
        group.bench_with_input(
            BenchmarkId::new("knowledge_store_flat", count),
            &count,
            |b, &n| {
                b.iter(|| {
                    let store = KnowledgeStore::open_memory().unwrap();
                    let base_ts = 1700000000;
                    for i in 0..n {
                        let entry = make_entry(i, base_ts + i as i64 * 60);
                        store.store(&entry).unwrap();
                    }
                    black_box(store.count().unwrap());
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("temporal_tree", count), &count, |b, &n| {
            b.iter(|| {
                let tree = TemporalTree::open_memory().unwrap();
                let base_ts = 1700000000;
                for i in 0..n {
                    let ts = base_ts + i as i64 * 60;
                    tree.insert_fact(
                        TreeType::Session,
                        "bench-session",
                        &format!(
                            "Component {} behaves differently under load {}.",
                            i % 20,
                            i % 5
                        ),
                        ts,
                    )
                    .unwrap();
                }
                black_box(tree.count().unwrap());
            });
        });
    }

    group.finish();
}

fn bench_temporal_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("temporal_query");

    let count = 1000;
    let base_ts: i64 = 1700000000;

    // Pre-populate KnowledgeStore
    let ks = KnowledgeStore::open_memory().unwrap();
    for i in 0..count {
        ks.store(&make_entry(i, base_ts + i as i64 * 60)).unwrap();
    }

    // Pre-populate TemporalTree
    let tt = TemporalTree::open_memory().unwrap();
    for i in 0..count {
        let ts = base_ts + i as i64 * 60;
        tt.insert_fact(
            TreeType::Session,
            "bench-session",
            &format!("Component {} under load {}.", i % 20, i % 5),
            ts,
        )
        .unwrap();
    }
    // Simulate summarization
    for node in tt.dirty_nodes(TreeType::Session, "bench-session").unwrap() {
        tt.update_summary(
            node.id,
            "Summary of session activity covering components and load conditions",
        )
        .unwrap();
    }

    // Query: "find facts in the last 100 minutes"
    let range_start = base_ts + 900 * 60; // last ~100 entries
    let range_end = base_ts + count as i64 * 60;

    group.bench_function("knowledge_store_search", |b| {
        b.iter(|| {
            let results = ks.search(black_box("component load")).unwrap();
            black_box(results.len());
        });
    });

    group.bench_function("temporal_tree_leaves_in_range", |b| {
        b.iter(|| {
            let results = tt
                .leaves_in_range(
                    TreeType::Session,
                    "bench-session",
                    black_box(range_start),
                    black_box(range_end),
                )
                .unwrap();
            black_box(results.len());
        });
    });

    group.bench_function("temporal_tree_search_roots", |b| {
        b.iter(|| {
            let results = tt
                .search_roots(TreeType::Session, black_box("component"), 10)
                .unwrap();
            black_box(results.len());
        });
    });

    group.bench_function("temporal_tree_browse", |b| {
        b.iter(|| {
            let results = tt
                .browse_tree(TreeType::Session, black_box("bench-session"))
                .unwrap();
            black_box(results.len());
        });
    });

    group.finish();
}

fn bench_multi_tree_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_tree_write");

    let entity_count = 50;
    let facts_per_entity = 20;

    group.bench_function("knowledge_store_flat", |b| {
        b.iter(|| {
            let store = KnowledgeStore::open_memory().unwrap();
            let base_ts = 1700000000;
            for e in 0..entity_count {
                for f in 0..facts_per_entity {
                    let i = e * facts_per_entity + f;
                    let entry = make_entry(i, base_ts + i as i64 * 60);
                    store.store(&entry).unwrap();
                }
            }
            black_box(store.count().unwrap());
        });
    });

    group.bench_function("temporal_tree_per_entity", |b| {
        b.iter(|| {
            let tree = TemporalTree::open_memory().unwrap();
            let base_ts = 1700000000;
            for e in 0..entity_count {
                let name = format!("entity-{e}");
                for f in 0..facts_per_entity {
                    let i = e * facts_per_entity + f;
                    let ts = base_ts + i as i64 * 60;
                    tree.insert_fact(
                        TreeType::Entity,
                        &name,
                        &format!("Entity {e} fact {f}: status update"),
                        ts,
                    )
                    .unwrap();
                }
            }
            black_box(tree.count().unwrap());
        });
    });

    group.finish();
}

fn bench_tree_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_depth");
    group.sample_size(20);
    let count = 1000;
    let base_ts: i64 = 1700000000;

    for max_children in [4, 8, 16, 1000] {
        let label = if max_children >= 1000 {
            "flat_2level".to_string()
        } else {
            format!("branch_{max_children}")
        };

        group.bench_with_input(
            BenchmarkId::new("write", &label),
            &max_children,
            |b, &mc| {
                b.iter(|| {
                    let tree = TemporalTree::open_memory().unwrap().with_max_children(mc);
                    for i in 0..count {
                        tree.insert_fact(
                            TreeType::Session,
                            "s1",
                            &format!("Component {} load {}.", i % 20, i % 5),
                            base_ts + i as i64 * 60,
                        )
                        .unwrap();
                    }
                    black_box(tree.count().unwrap());
                });
            },
        );
    }

    // Pre-populate trees for query benchmarks
    let mut trees = Vec::new();
    for max_children in [4, 8, 16, 1000] {
        let tree = TemporalTree::open_memory()
            .unwrap()
            .with_max_children(max_children);
        for i in 0..count {
            tree.insert_fact(
                TreeType::Session,
                "s1",
                &format!("Component {} load {}.", i % 20, i % 5),
                base_ts + i as i64 * 60,
            )
            .unwrap();
        }
        trees.push((max_children, tree));
    }

    let range_start = base_ts + 900 * 60;
    let range_end = base_ts + count as i64 * 60;

    for (mc, tree) in &trees {
        let label = if *mc >= 1000 {
            "flat_2level".to_string()
        } else {
            format!("branch_{mc}")
        };

        group.bench_with_input(BenchmarkId::new("range_query", &label), mc, |b, _| {
            b.iter(|| {
                let results = tree
                    .leaves_in_range(
                        TreeType::Session,
                        "s1",
                        black_box(range_start),
                        black_box(range_end),
                    )
                    .unwrap();
                black_box(results.len());
            });
        });
    }

    for (mc, tree) in &trees {
        let label = if *mc >= 1000 {
            "flat_2level".to_string()
        } else {
            format!("branch_{mc}")
        };

        group.bench_with_input(BenchmarkId::new("browse", &label), mc, |b, _| {
            b.iter(|| {
                let results = tree
                    .browse_tree(TreeType::Session, black_box("s1"))
                    .unwrap();
                black_box(results.len());
            });
        });
    }

    group.finish();
}

fn bench_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("scale");
    let base_ts: i64 = 1700000000;

    // --- Write benchmarks ---
    for count in [1000, 10000, 100000] {
        // 2 samples for >=100K to avoid thermal throttling (~4 min instead of 40)
        group.sample_size(if count >= 100000 { 2 } else { 10 });
        group.bench_with_input(BenchmarkId::new("tt_batch_b64", count), &count, |b, &n| {
            b.iter(|| {
                let tree = TemporalTree::open_memory().unwrap();
                let facts: Vec<(String, i64)> = (0..n)
                    .map(|i| {
                        (
                            format!("Component {} load {}.", i % 20, i % 5),
                            base_ts + i as i64 * 60,
                        )
                    })
                    .collect();
                let refs: Vec<(&str, i64)> = facts.iter().map(|(s, t)| (s.as_str(), *t)).collect();
                tree.insert_facts(TreeType::Session, "s1", &refs).unwrap();
                black_box(tree.count().unwrap());
            });
        });

        // KS individual insert (skip at 100K+ — too slow)
        if count <= 10000 {
            group.bench_with_input(BenchmarkId::new("ks_write", count), &count, |b, &n| {
                b.iter(|| {
                    let store = KnowledgeStore::open_memory().unwrap();
                    for i in 0..n {
                        store
                            .store(&make_entry(i, base_ts + i as i64 * 60))
                            .unwrap();
                    }
                    black_box(store.count().unwrap());
                });
            });
        }
    }

    // --- Query benchmarks at scale (pre-populate once, bench queries) ---
    // Skip 1M — pre-population takes 163s per benchmark group
    for count in [1000, 10000, 100000] {
        group.sample_size(10);
        // Pre-populate temporal tree via batch insert
        let tt = TemporalTree::open_memory().unwrap();
        let facts: Vec<(String, i64)> = (0..count)
            .map(|i| {
                (
                    format!("Component {} load {}.", i % 20, i % 5),
                    base_ts + i as i64 * 60,
                )
            })
            .collect();
        let refs: Vec<(&str, i64)> = facts.iter().map(|(s, t)| (s.as_str(), *t)).collect();
        tt.insert_facts(TreeType::Session, "s1", &refs).unwrap();

        let range_start = base_ts + (count as i64 - 100) * 60;
        let range_end = base_ts + count as i64 * 60;

        group.bench_with_input(BenchmarkId::new("tt_range", count), &count, |b, _| {
            b.iter(|| {
                black_box(
                    tt.leaves_in_range(
                        TreeType::Session,
                        "s1",
                        black_box(range_start),
                        black_box(range_end),
                    )
                    .unwrap()
                    .len(),
                );
            });
        });

        // KS query (skip at 100K+ — FTS5 scan is very slow)
        if count <= 10000 {
            let ks = KnowledgeStore::open_memory().unwrap();
            for i in 0..count {
                ks.store(&make_entry(i, base_ts + i as i64 * 60)).unwrap();
            }

            group.bench_with_input(BenchmarkId::new("ks_search", count), &count, |b, _| {
                b.iter(|| black_box(ks.search(black_box("component")).unwrap().len()));
            });
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_write_throughput,
    bench_temporal_query,
    bench_multi_tree_write,
    bench_tree_depth,
    bench_scale
);
criterion_main!(benches);
