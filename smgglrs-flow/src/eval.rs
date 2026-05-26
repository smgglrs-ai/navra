//! Statistical evaluation for flow comparison experiments.
//!
//! Computes precision, token efficiency, and confidence intervals
//! across multiple runs. Used for S9 (statistical significance)
//! in paper evaluation.

use serde::{Deserialize, Serialize};

/// Metrics from a single flow run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetrics {
    /// Project name or identifier.
    pub project: String,
    /// Run index (0-based).
    pub run: usize,
    /// Number of findings reported by the flow.
    pub findings_count: usize,
    /// Number of findings confirmed as real (true positives).
    pub true_positives: usize,
    /// Number of findings that were false positives.
    pub false_positives: usize,
    /// Total tokens consumed (input + output across all agents).
    pub total_tokens: u64,
    /// Wall clock duration in seconds.
    pub duration_secs: u64,
    /// Number of specialists used.
    pub specialists: usize,
}

impl RunMetrics {
    pub fn precision(&self) -> f64 {
        if self.findings_count == 0 {
            return 0.0;
        }
        self.true_positives as f64 / self.findings_count as f64
    }

    pub fn tokens_per_finding(&self) -> f64 {
        if self.true_positives == 0 {
            return f64::INFINITY;
        }
        self.total_tokens as f64 / self.true_positives as f64
    }
}

/// Summary statistics for a set of runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalSummary {
    pub n: usize,
    pub mean_precision: f64,
    pub std_precision: f64,
    pub mean_tokens_per_finding: f64,
    pub std_tokens_per_finding: f64,
    pub mean_findings: f64,
    pub std_findings: f64,
    /// 95% confidence interval for precision (mean ± ci).
    pub precision_ci_95: f64,
}

/// Compute summary statistics with confidence intervals.
pub fn summarize(runs: &[RunMetrics]) -> EvalSummary {
    let n = runs.len();
    if n == 0 {
        return EvalSummary {
            n: 0,
            mean_precision: 0.0,
            std_precision: 0.0,
            mean_tokens_per_finding: 0.0,
            std_tokens_per_finding: 0.0,
            mean_findings: 0.0,
            std_findings: 0.0,
            precision_ci_95: 0.0,
        };
    }

    let precisions: Vec<f64> = runs.iter().map(|r| r.precision()).collect();
    let tpf: Vec<f64> = runs
        .iter()
        .map(|r| r.tokens_per_finding())
        .filter(|v| v.is_finite())
        .collect();
    let findings: Vec<f64> = runs.iter().map(|r| r.true_positives as f64).collect();

    let (mean_p, std_p) = mean_std(&precisions);
    let (mean_t, std_t) = mean_std(&tpf);
    let (mean_f, std_f) = mean_std(&findings);

    // 95% CI using t-distribution approximation
    // For small n, t_0.025 ≈ 2.0 (n=∞), 2.26 (n=10), 2.78 (n=5), 4.30 (n=3)
    let t_value = match n {
        1 => 12.71,
        2 => 4.30,
        3 => 3.18,
        4 => 2.78,
        5 => 2.57,
        6..=10 => 2.26,
        11..=30 => 2.09,
        _ => 1.96,
    };
    let ci = t_value * std_p / (n as f64).sqrt();

    EvalSummary {
        n,
        mean_precision: mean_p,
        std_precision: std_p,
        mean_tokens_per_finding: mean_t,
        std_tokens_per_finding: std_t,
        mean_findings: mean_f,
        std_findings: std_f,
        precision_ci_95: ci,
    }
}

/// Compare two evaluation summaries and report whether the difference
/// is statistically significant using Welch's t-test.
pub fn compare(a: &EvalSummary, b: &EvalSummary) -> ComparisonResult {
    let t_stat = if a.std_precision == 0.0 && b.std_precision == 0.0 {
        0.0
    } else {
        let se = ((a.std_precision.powi(2) / a.n.max(1) as f64)
            + (b.std_precision.powi(2) / b.n.max(1) as f64))
            .sqrt();
        if se == 0.0 {
            0.0
        } else {
            (a.mean_precision - b.mean_precision).abs() / se
        }
    };

    // Welch-Satterthwaite degrees of freedom
    let df = if a.std_precision == 0.0 && b.std_precision == 0.0 {
        1.0
    } else {
        let s1 = a.std_precision.powi(2) / a.n.max(1) as f64;
        let s2 = b.std_precision.powi(2) / b.n.max(1) as f64;
        let num = (s1 + s2).powi(2);
        let den = s1.powi(2) / (a.n.max(1) - 1).max(1) as f64
            + s2.powi(2) / (b.n.max(1) - 1).max(1) as f64;
        if den == 0.0 {
            1.0
        } else {
            num / den
        }
    };

    // Approximate p-value from t-distribution (two-tailed)
    // Using simplified approximation: p ≈ 2 * (1 - Φ(t)) for large df
    let significant_at_05 = t_stat > 2.0 && df >= 2.0;

    ComparisonResult {
        t_statistic: t_stat,
        degrees_of_freedom: df,
        significant_at_05,
        precision_diff: a.mean_precision - b.mean_precision,
        efficiency_ratio: if b.mean_tokens_per_finding == 0.0 {
            0.0
        } else {
            a.mean_tokens_per_finding / b.mean_tokens_per_finding
        },
    }
}

/// Result of comparing two evaluation conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub t_statistic: f64,
    pub degrees_of_freedom: f64,
    pub significant_at_05: bool,
    pub precision_diff: f64,
    pub efficiency_ratio: f64,
}

fn mean_std(values: &[f64]) -> (f64, f64) {
    let n = values.len() as f64;
    if n == 0.0 {
        return (0.0, 0.0);
    }
    let mean = values.iter().sum::<f64>() / n;
    if n <= 1.0 {
        return (mean, 0.0);
    }
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var.sqrt())
}

/// Format an evaluation summary for display.
pub fn format_summary(name: &str, summary: &EvalSummary) -> String {
    format!(
        "{name} (n={n}):\n  \
         Precision: {p:.3} ± {ci:.3} (95% CI)\n  \
         Findings/run: {f:.1} ± {fs:.1}\n  \
         Tokens/finding: {t:.0} ± {ts:.0}",
        n = summary.n,
        p = summary.mean_precision,
        ci = summary.precision_ci_95,
        f = summary.mean_findings,
        fs = summary.std_findings,
        t = summary.mean_tokens_per_finding,
        ts = summary.std_tokens_per_finding,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_runs() -> Vec<RunMetrics> {
        vec![
            RunMetrics {
                project: "project-a".into(),
                run: 0,
                findings_count: 10,
                true_positives: 8,
                false_positives: 2,
                total_tokens: 500_000,
                duration_secs: 300,
                specialists: 5,
            },
            RunMetrics {
                project: "project-a".into(),
                run: 1,
                findings_count: 12,
                true_positives: 9,
                false_positives: 3,
                total_tokens: 520_000,
                duration_secs: 310,
                specialists: 5,
            },
            RunMetrics {
                project: "project-a".into(),
                run: 2,
                findings_count: 11,
                true_positives: 8,
                false_positives: 3,
                total_tokens: 480_000,
                duration_secs: 290,
                specialists: 5,
            },
        ]
    }

    #[test]
    fn summarize_computes_ci() {
        let runs = sample_runs();
        let summary = summarize(&runs);

        assert_eq!(summary.n, 3);
        assert!(
            summary.mean_precision > 0.7 && summary.mean_precision < 0.9,
            "precision should be ~0.8, got {}",
            summary.mean_precision
        );
        assert!(summary.precision_ci_95 > 0.0, "CI should be positive");
        assert!(
            summary.std_precision < 0.1,
            "std should be small for similar runs"
        );

        println!("\n{}", format_summary("Dynamic", &summary));
    }

    #[test]
    fn compare_detects_significant_difference() {
        let good = summarize(&[
            RunMetrics {
                project: "p".into(),
                run: 0,
                findings_count: 10,
                true_positives: 9,
                false_positives: 1,
                total_tokens: 200_000,
                duration_secs: 100,
                specialists: 3,
            },
            RunMetrics {
                project: "p".into(),
                run: 1,
                findings_count: 10,
                true_positives: 8,
                false_positives: 2,
                total_tokens: 210_000,
                duration_secs: 110,
                specialists: 3,
            },
            RunMetrics {
                project: "p".into(),
                run: 2,
                findings_count: 10,
                true_positives: 9,
                false_positives: 1,
                total_tokens: 195_000,
                duration_secs: 105,
                specialists: 3,
            },
        ]);
        let bad = summarize(&[
            RunMetrics {
                project: "p".into(),
                run: 0,
                findings_count: 10,
                true_positives: 3,
                false_positives: 7,
                total_tokens: 500_000,
                duration_secs: 300,
                specialists: 8,
            },
            RunMetrics {
                project: "p".into(),
                run: 1,
                findings_count: 10,
                true_positives: 4,
                false_positives: 6,
                total_tokens: 520_000,
                duration_secs: 310,
                specialists: 8,
            },
            RunMetrics {
                project: "p".into(),
                run: 2,
                findings_count: 10,
                true_positives: 3,
                false_positives: 7,
                total_tokens: 480_000,
                duration_secs: 290,
                specialists: 8,
            },
        ]);

        let result = compare(&good, &bad);
        println!("\n--- Comparison ---");
        println!("{}", format_summary("Dynamic", &good));
        println!("{}", format_summary("Hardcoded", &bad));
        println!(
            "t={:.2}, df={:.1}, significant={}, diff={:.3}, efficiency={:.2}x",
            result.t_statistic,
            result.degrees_of_freedom,
            result.significant_at_05,
            result.precision_diff,
            result.efficiency_ratio
        );

        assert!(
            result.significant_at_05,
            "Large precision difference should be significant"
        );
        assert!(
            result.precision_diff > 0.4,
            "Dynamic should have much higher precision"
        );
        assert!(
            result.efficiency_ratio < 0.5,
            "Dynamic should use fewer tokens per finding"
        );
    }

    #[test]
    fn compare_similar_runs_not_significant() {
        let a = summarize(&sample_runs());
        let b = summarize(&[
            RunMetrics {
                project: "p".into(),
                run: 0,
                findings_count: 10,
                true_positives: 7,
                false_positives: 3,
                total_tokens: 510_000,
                duration_secs: 305,
                specialists: 5,
            },
            RunMetrics {
                project: "p".into(),
                run: 1,
                findings_count: 11,
                true_positives: 8,
                false_positives: 3,
                total_tokens: 490_000,
                duration_secs: 295,
                specialists: 5,
            },
            RunMetrics {
                project: "p".into(),
                run: 2,
                findings_count: 10,
                true_positives: 8,
                false_positives: 2,
                total_tokens: 500_000,
                duration_secs: 300,
                specialists: 5,
            },
        ]);

        let result = compare(&a, &b);
        assert!(
            !result.significant_at_05,
            "Similar runs should not show significant difference"
        );
    }
}
