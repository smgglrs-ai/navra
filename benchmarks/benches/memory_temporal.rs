//! Benchmark: TemporalTree vs KnowledgeStore
//!
//! Compares write throughput, temporal queries, and retrieval for
//! flat KnowledgeStore vs hierarchical TemporalTree.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use smgglrs_memory::temporal::{TemporalTree, TreeType};
use smgglrs_memory::{KnowledgeStore, MemoryEntry, MemoryType};

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

        group.bench_with_input(
            BenchmarkId::new("temporal_tree", count),
            &count,
            |b, &n| {
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
            },
        );
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
        tt.update_summary(node.id, "Summary of session activity covering components and load conditions").unwrap();
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
        let tree = TemporalTree::open_memory().unwrap().with_max_children(max_children);
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

        group.bench_with_input(
            BenchmarkId::new("range_query", &label),
            mc,
            |b, _| {
                b.iter(|| {
                    let results = tree
                        .leaves_in_range(TreeType::Session, "s1", black_box(range_start), black_box(range_end))
                        .unwrap();
                    black_box(results.len());
                });
            },
        );
    }

    for (mc, tree) in &trees {
        let label = if *mc >= 1000 {
            "flat_2level".to_string()
        } else {
            format!("branch_{mc}")
        };

        group.bench_with_input(
            BenchmarkId::new("browse", &label),
            mc,
            |b, _| {
                b.iter(|| {
                    let results = tree
                        .browse_tree(TreeType::Session, black_box("s1"))
                        .unwrap();
                    black_box(results.len());
                });
            },
        );
    }

    group.finish();
}

fn bench_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("scale");
    group.sample_size(10);
    let base_ts: i64 = 1700000000;

    for count in [1000, 5000, 10000] {
        // Flat KnowledgeStore
        group.bench_with_input(
            BenchmarkId::new("ks_write", count),
            &count,
            |b, &n| {
                b.iter(|| {
                    let store = KnowledgeStore::open_memory().unwrap();
                    for i in 0..n {
                        store.store(&make_entry(i, base_ts + i as i64 * 60)).unwrap();
                    }
                    black_box(store.count().unwrap());
                });
            },
        );

        // Temporal tree (default max_children=64)
        group.bench_with_input(
            BenchmarkId::new("tt_write_b64", count),
            &count,
            |b, &n| {
                b.iter(|| {
                    let tree = TemporalTree::open_memory().unwrap();
                    for i in 0..n {
                        tree.insert_fact(
                            TreeType::Session, "s1",
                            &format!("Component {} load {}.", i % 20, i % 5),
                            base_ts + i as i64 * 60,
                        ).unwrap();
                    }
                    black_box(tree.count().unwrap());
                });
            },
        );

        // Temporal tree (branching=16)
        group.bench_with_input(
            BenchmarkId::new("tt_write_b16", count),
            &count,
            |b, &n| {
                b.iter(|| {
                    let tree = TemporalTree::open_memory().unwrap().with_max_children(16);
                    for i in 0..n {
                        tree.insert_fact(
                            TreeType::Session, "s1",
                            &format!("Component {} load {}.", i % 20, i % 5),
                            base_ts + i as i64 * 60,
                        ).unwrap();
                    }
                    black_box(tree.count().unwrap());
                });
            },
        );
    }

    // Query benchmarks at each scale
    for count in [1000, 5000, 10000] {
        let ks = KnowledgeStore::open_memory().unwrap();
        for i in 0..count {
            ks.store(&make_entry(i, base_ts + i as i64 * 60)).unwrap();
        }

        let tt64 = TemporalTree::open_memory().unwrap();
        let tt16 = TemporalTree::open_memory().unwrap().with_max_children(16);
        for i in 0..count {
            let ts = base_ts + i as i64 * 60;
            let content = format!("Component {} load {}.", i % 20, i % 5);
            tt64.insert_fact(TreeType::Session, "s1", &content, ts).unwrap();
            tt16.insert_fact(TreeType::Session, "s1", &content, ts).unwrap();
        }

        let range_start = base_ts + (count as i64 - 100) * 60;
        let range_end = base_ts + count as i64 * 60;

        group.bench_with_input(
            BenchmarkId::new("ks_search", count),
            &count,
            |b, _| {
                b.iter(|| black_box(ks.search(black_box("component")).unwrap().len()));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("tt_range_b64", count),
            &count,
            |b, _| {
                b.iter(|| {
                    black_box(tt64.leaves_in_range(TreeType::Session, "s1", black_box(range_start), black_box(range_end)).unwrap().len());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("tt_range_b16", count),
            &count,
            |b, _| {
                b.iter(|| {
                    black_box(tt16.leaves_in_range(TreeType::Session, "s1", black_box(range_start), black_box(range_end)).unwrap().len());
                });
            },
        );
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
