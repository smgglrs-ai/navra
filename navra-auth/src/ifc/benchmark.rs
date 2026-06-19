//! IFC benchmark harness.
//!
//! Evaluates the IFC pipeline against a corpus of attack and benign
//! vectors. Computes precision, recall, and F1 per category and
//! overall.

use super::{TaintTracker, TaintedWritePolicy};
use crate::ifc::corpus::{BenchmarkVector, Category, DefenseLayer, ExpectedOutcome, Invariant};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Default)]
pub struct CategoryMetrics {
    pub tp: u32,
    pub fp: u32,
    pub tn: u32,
    pub fn_: u32,
}

impl CategoryMetrics {
    pub fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            1.0
        } else {
            self.tp as f64 / denom as f64
        }
    }

    pub fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            1.0
        } else {
            self.tp as f64 / denom as f64
        }
    }

    pub fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }

    pub fn total(&self) -> u32 {
        self.tp + self.fp + self.tn + self.fn_
    }
}

#[derive(Debug, Clone)]
pub struct VectorResult {
    pub id: &'static str,
    pub category: Category,
    pub expected: ExpectedOutcome,
    pub actual: ExpectedOutcome,
    pub correct: bool,
    pub defense_layer: DefenseLayer,
    pub invariant: Invariant,
}

#[derive(Debug, Clone)]
pub struct BenchmarkReport {
    pub by_category: BTreeMap<String, CategoryMetrics>,
    pub by_invariant: BTreeMap<String, CategoryMetrics>,
    pub overall: CategoryMetrics,
    pub results: Vec<VectorResult>,
    pub honest_gaps: Vec<&'static str>,
}

impl BenchmarkReport {
    pub fn macro_f1(&self) -> f64 {
        if self.by_category.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.by_category.values().map(|m| m.f1()).sum();
        sum / self.by_category.len() as f64
    }
}

impl fmt::Display for BenchmarkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "IFC Adversarial Benchmark Report")?;
        writeln!(f, "================================")?;
        writeln!(f)?;

        writeln!(
            f,
            "{:<28} {:>4} {:>4} {:>4} {:>4} {:>8} {:>8} {:>8}",
            "Category", "TP", "FP", "TN", "FN", "Prec", "Recall", "F1"
        )?;
        writeln!(f, "{}", "-".repeat(76))?;

        for (cat, m) in &self.by_category {
            writeln!(
                f,
                "{:<28} {:>4} {:>4} {:>4} {:>4} {:>8.3} {:>8.3} {:>8.3}",
                cat,
                m.tp,
                m.fp,
                m.tn,
                m.fn_,
                m.precision(),
                m.recall(),
                m.f1()
            )?;
        }

        writeln!(f, "{}", "-".repeat(76))?;
        writeln!(
            f,
            "{:<28} {:>4} {:>4} {:>4} {:>4} {:>8.3} {:>8.3} {:>8.3}",
            "OVERALL",
            self.overall.tp,
            self.overall.fp,
            self.overall.tn,
            self.overall.fn_,
            self.overall.precision(),
            self.overall.recall(),
            self.overall.f1()
        )?;
        writeln!(f)?;
        writeln!(f, "Macro-averaged F1: {:.3}", self.macro_f1())?;
        writeln!(
            f,
            "Total vectors: {} ({} attack, {} benign)",
            self.overall.total(),
            self.overall.tp + self.overall.fn_,
            self.overall.tn + self.overall.fp
        )?;

        if !self.honest_gaps.is_empty() {
            writeln!(f)?;
            writeln!(
                f,
                "Honest gaps (IFC blocks, safety layer missed): {}",
                self.honest_gaps.len()
            )?;
            for id in &self.honest_gaps {
                writeln!(f, "  - {id}")?;
            }
        }

        writeln!(f)?;
        writeln!(f, "By invariant:")?;
        for (inv, m) in &self.by_invariant {
            writeln!(f, "  {:<32} F1={:.3} ({} vectors)", inv, m.f1(), m.total())?;
        }

        Ok(())
    }
}

fn evaluate_vector(v: &BenchmarkVector) -> ExpectedOutcome {
    let mut tracker = TaintTracker::new();
    for label in &v.session.read_labels {
        tracker.absorb(*label);
    }

    if let Some(clearance) = v.session.read_clearance {
        let level = tracker.level();
        if level.confidentiality > clearance {
            return ExpectedOutcome::Blocked;
        }
    }

    match v.session.write_policy {
        TaintedWritePolicy::Allow => {
            // No IFC enforcement — writes always allowed
        }
        TaintedWritePolicy::Approve | TaintedWritePolicy::Deny => {
            let level = tracker.level();
            if tracker.is_untrusted() || !level.can_write_to(v.session.write_target_clearance) {
                return ExpectedOutcome::Blocked;
            }
        }
    }

    ExpectedOutcome::Allowed
}

pub fn run_benchmark(vectors: &[BenchmarkVector]) -> BenchmarkReport {
    let mut by_category: BTreeMap<String, CategoryMetrics> = BTreeMap::new();
    let mut by_invariant: BTreeMap<String, CategoryMetrics> = BTreeMap::new();
    let mut overall = CategoryMetrics::default();
    let mut results = Vec::with_capacity(vectors.len());
    let mut honest_gaps = Vec::new();

    for v in vectors {
        let actual = evaluate_vector(v);
        let correct = actual == v.expected;

        let cat_key = format!("{:?}", v.category);
        let inv_key = format!("{:?}", v.invariant);
        let cat_metrics = by_category.entry(cat_key).or_default();
        let inv_metrics = by_invariant.entry(inv_key).or_default();

        match (v.expected, actual) {
            (ExpectedOutcome::Blocked, ExpectedOutcome::Blocked) => {
                cat_metrics.tp += 1;
                inv_metrics.tp += 1;
                overall.tp += 1;
            }
            (ExpectedOutcome::Blocked, ExpectedOutcome::Allowed) => {
                cat_metrics.fn_ += 1;
                inv_metrics.fn_ += 1;
                overall.fn_ += 1;
            }
            (ExpectedOutcome::Allowed, ExpectedOutcome::Blocked) => {
                cat_metrics.fp += 1;
                inv_metrics.fp += 1;
                overall.fp += 1;
            }
            (ExpectedOutcome::Allowed, ExpectedOutcome::Allowed) => {
                cat_metrics.tn += 1;
                inv_metrics.tn += 1;
                overall.tn += 1;
            }
        }

        if v.defense_layer == DefenseLayer::HonestGap && actual == ExpectedOutcome::Blocked {
            honest_gaps.push(v.id);
        }

        results.push(VectorResult {
            id: v.id,
            category: v.category,
            expected: v.expected,
            actual,
            correct,
            defense_layer: v.defense_layer,
            invariant: v.invariant,
        });
    }

    BenchmarkReport {
        by_category,
        by_invariant,
        overall,
        results,
        honest_gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ifc::corpus;

    #[test]
    fn benchmark_runs_without_panic() {
        let corpus = corpus::full_corpus();
        let report = run_benchmark(&corpus);
        assert_eq!(report.results.len(), corpus.len());
    }

    #[test]
    fn all_attack_vectors_blocked() {
        let mut corpus = corpus::navra_corpus();
        corpus.extend(corpus::mvar_corpus());
        let report = run_benchmark(&corpus);
        assert_eq!(report.overall.fn_, 0, "no attack vectors should be missed");
    }

    #[test]
    fn no_false_positives_on_benign() {
        let corpus = corpus::benign_corpus();
        let report = run_benchmark(&corpus);
        assert_eq!(
            report.overall.fp, 0,
            "no benign operations should be blocked"
        );
    }

    #[test]
    fn perfect_f1_on_full_corpus() {
        let corpus = corpus::full_corpus();
        let report = run_benchmark(&corpus);
        assert!(
            (report.overall.f1() - 1.0).abs() < f64::EPSILON,
            "expected perfect F1 on unit-level corpus, got {}",
            report.overall.f1()
        );
    }
}
