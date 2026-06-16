//! IFC adversarial corpus benchmark integration test.
//!
//! Runs the full 261-vector corpus (navra + MVAR + benign) through
//! the IFC pipeline and asserts minimum F1 thresholds. Prints a
//! formatted report table for CI visibility.

use navra_auth::ifc::benchmark::run_benchmark;
use navra_auth::ifc::corpus;

#[test]
fn ifc_benchmark_full_corpus() {
    let vectors = corpus::full_corpus();
    let report = run_benchmark(&vectors);

    eprintln!("\n{report}");

    assert_eq!(
        report.overall.fn_, 0,
        "IFC benchmark: {} attack vectors were not blocked",
        report.overall.fn_
    );
    assert_eq!(
        report.overall.fp, 0,
        "IFC benchmark: {} benign operations were incorrectly blocked",
        report.overall.fp
    );

    let f1 = report.overall.f1();
    assert!(
        f1 >= 0.8,
        "IFC benchmark: overall F1 {f1:.3} below minimum threshold 0.8"
    );

    let macro_f1 = report.macro_f1();
    assert!(
        macro_f1 >= 0.8,
        "IFC benchmark: macro-averaged F1 {macro_f1:.3} below minimum threshold 0.8"
    );

    for result in &report.results {
        assert!(
            result.correct,
            "IFC benchmark: vector {} ({:?}) expected {:?}, got {:?}",
            result.id, result.category, result.expected, result.actual
        );
    }
}

#[test]
fn ifc_benchmark_navra_corpus_only() {
    let vectors = corpus::navra_corpus();
    let report = run_benchmark(&vectors);
    assert_eq!(report.overall.fn_, 0, "navra corpus: missed attacks");
    assert!(
        report.overall.f1() >= 0.8,
        "navra corpus F1: {:.3}",
        report.overall.f1()
    );
}

#[test]
fn ifc_benchmark_mvar_corpus_only() {
    let vectors = corpus::mvar_corpus();
    let report = run_benchmark(&vectors);
    assert_eq!(report.overall.fn_, 0, "MVAR corpus: missed attacks");
    assert!(
        report.overall.f1() >= 0.8,
        "MVAR corpus F1: {:.3}",
        report.overall.f1()
    );
}
