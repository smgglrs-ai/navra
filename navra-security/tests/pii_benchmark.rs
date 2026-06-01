//! PII detection benchmark: precision, recall, F1 per category.
//!
//! Runs the regex PII filter against labeled test data and reports
//! metrics. This is the S7 evaluation for paper submission.

use navra_security::safety::ner::load_ner_filter;
use navra_security::safety::{ContentFilter, FilterContext, PiiFilter};
use std::path::Path;

/// A labeled test case: text with expected PII findings.
struct TestCase {
    text: &'static str,
    expected: Vec<(&'static str, &'static str)>, // (category, matched_text)
}

fn default_ctx() -> FilterContext<'static> {
    FilterContext {
        agent_name: "bench",
        operation: "test",
        path: None,
    }
}

fn test_cases() -> Vec<TestCase> {
    vec![
        // --- True positives: text containing PII ---

        // SSN
        TestCase {
            text: "His SSN is 123-45-6789 and he lives in NYC.",
            expected: vec![("ssn", "123-45-6789")],
        },
        // Credit card (Visa, valid Luhn)
        TestCase {
            text: "Card number: 4111111111111111 expiry 12/28",
            expected: vec![("credit-card", "4111111111111111")],
        },
        // Email
        TestCase {
            text: "Contact jean.dupont@example.com for details.",
            expected: vec![("email", "jean.dupont@example.com")],
        },
        // Phone (US)
        TestCase {
            text: "Call me at 555-123-4567 after 5pm.",
            expected: vec![("phone", "555-123-4567")],
        },
        // French NIR (compact format)
        TestCase {
            text: "Son numéro NIR est 185017501200542.",
            expected: vec![("nir", "185017501200542")],
        },
        // IBAN (FR)
        TestCase {
            text: "Virement IBAN: FR76 3000 6000 0112 3456 7890 189",
            expected: vec![("iban", "FR76 3000 6000 0112 3456 7890 189")],
        },
        // EU phone
        TestCase {
            text: "Appelez le +33 612345678 pour confirmer.",
            expected: vec![("phone-eu", "+33 612345678")],
        },
        // SIRET (valid Luhn: 732 829 320 00074)
        TestCase {
            text: "SIRET de l'entreprise: 73282932000074.",
            expected: vec![("siret", "73282932000074")],
        },
        // Passport (French format)
        TestCase {
            text: "Passport number 12AB34567 issued 2024.",
            expected: vec![("passport", "12AB34567")],
        },
        // IP address (public)
        TestCase {
            text: "Server at 203.0.113.42 is down.",
            expected: vec![("ip-address", "203.0.113.42")],
        },
        // Multiple PII in one text
        TestCase {
            text: "Email: alice@corp.com, phone: +49 1701234567, SSN: 078-05-1120",
            expected: vec![
                ("email", "alice@corp.com"),
                ("phone-eu", "+49 1701234567"),
                ("ssn", "078-05-1120"),
            ],
        },
        // --- True negatives: text without PII ---
        TestCase {
            text: "The function returns an error code 404.",
            expected: vec![],
        },
        TestCase {
            text: "Version 1.23.456 released on 2024-01-15.",
            expected: vec![],
        },
        TestCase {
            text: "UUID: 550e8400-e29b-41d4-a716-446655440000",
            expected: vec![],
        },
        TestCase {
            text: "Localhost 127.0.0.1 is always available.",
            expected: vec![],
        },
        TestCase {
            text: "The hash is a1b2c3d4e5f6 and the build number is 20240115.",
            expected: vec![],
        },
        TestCase {
            text: "Port 8080 is used for the development server.",
            expected: vec![],
        },
        TestCase {
            text: "Error at line 123, column 45 in parser.rs",
            expected: vec![],
        },
        // --- Edge cases ---

        // Credit card with wrong Luhn (should NOT match)
        TestCase {
            text: "Number 4111111111111112 is invalid.",
            expected: vec![],
        },
        // Private IP (should NOT match)
        TestCase {
            text: "Internal host at 192.168.1.100.",
            expected: vec![],
        },
        // SSN-like but in structured data context (timestamp)
        TestCase {
            text: "Timestamp 123-45-6789 in the log line 2024-01-15T10:30:00Z",
            expected: vec![], // context validator should reject
        },
    ]
}

#[derive(Default)]
struct CategoryMetrics {
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
}

impl CategoryMetrics {
    fn precision(&self) -> f64 {
        if self.true_positives + self.false_positives == 0 {
            1.0
        } else {
            self.true_positives as f64 / (self.true_positives + self.false_positives) as f64
        }
    }
    fn recall(&self) -> f64 {
        if self.true_positives + self.false_negatives == 0 {
            1.0
        } else {
            self.true_positives as f64 / (self.true_positives + self.false_negatives) as f64
        }
    }
    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

#[test]
fn pii_benchmark_precision_recall_f1() {
    let filter = PiiFilter::new();
    let ctx = default_ctx();
    let cases = test_cases();

    let mut metrics: std::collections::HashMap<String, CategoryMetrics> =
        std::collections::HashMap::new();
    let mut total = CategoryMetrics::default();
    let mut case_results: Vec<(usize, bool, String)> = Vec::new();

    for (i, case) in cases.iter().enumerate() {
        let findings = filter.scan(case.text, &ctx);
        let found_categories: Vec<(&str, String)> = findings
            .iter()
            .map(|f| (f.category.as_str(), case.text[f.start..f.end].to_string()))
            .collect();

        // Check expected matches
        let mut matched = vec![false; case.expected.len()];
        let mut finding_matched = vec![false; found_categories.len()];

        for (ei, (exp_cat, exp_text)) in case.expected.iter().enumerate() {
            for (fi, (found_cat, found_text)) in found_categories.iter().enumerate() {
                if finding_matched[fi] {
                    continue;
                }
                if *found_cat == *exp_cat && found_text.contains(exp_text) {
                    matched[ei] = true;
                    finding_matched[fi] = true;
                    let m = metrics.entry(exp_cat.to_string()).or_default();
                    m.true_positives += 1;
                    total.true_positives += 1;
                    break;
                }
            }
        }

        // False negatives: expected but not found
        for (ei, m) in matched.iter().enumerate() {
            if !m {
                let cat = case.expected[ei].0;
                let m = metrics.entry(cat.to_string()).or_default();
                m.false_negatives += 1;
                total.false_negatives += 1;
                case_results.push((
                    i,
                    false,
                    format!("FN: expected {}={}", cat, case.expected[ei].1),
                ));
            }
        }

        // False positives: found but not expected
        for (fi, m) in finding_matched.iter().enumerate() {
            if !m {
                let (cat, text) = &found_categories[fi];
                let m = metrics.entry(cat.to_string()).or_default();
                m.false_positives += 1;
                total.false_positives += 1;
                case_results.push((i, false, format!("FP: unexpected {}={}", cat, text)));
            }
        }

        if matched.iter().all(|m| *m)
            && finding_matched
                .iter()
                .all(|m| *m || case.expected.is_empty())
        {
            case_results.push((i, true, "OK".to_string()));
        }
    }

    // Report
    println!("\n=== PII Detection Benchmark (S7) ===\n");
    println!(
        "{:<15} {:>4} {:>4} {:>4} {:>8} {:>8} {:>8}",
        "Category", "TP", "FP", "FN", "Prec", "Recall", "F1"
    );
    println!("{}", "-".repeat(60));

    let mut cats: Vec<_> = metrics.keys().cloned().collect();
    cats.sort();
    for cat in &cats {
        let m = &metrics[cat];
        println!(
            "{:<15} {:>4} {:>4} {:>4} {:>8.3} {:>8.3} {:>8.3}",
            cat,
            m.true_positives,
            m.false_positives,
            m.false_negatives,
            m.precision(),
            m.recall(),
            m.f1()
        );
    }
    println!("{}", "-".repeat(60));
    println!(
        "{:<15} {:>4} {:>4} {:>4} {:>8.3} {:>8.3} {:>8.3}",
        "TOTAL",
        total.true_positives,
        total.false_positives,
        total.false_negatives,
        total.precision(),
        total.recall(),
        total.f1()
    );

    println!("\n--- Failures ---");
    for (i, ok, msg) in &case_results {
        if !ok {
            println!("  Case {}: {}", i, msg);
        }
    }
    let passed = case_results.iter().filter(|(_, ok, _)| *ok).count();
    println!("\n{}/{} cases fully correct", passed, cases.len());

    // Assertion: overall F1 should be above 0.80 (regex-only, no NER)
    assert!(
        total.f1() > 0.80,
        "Overall F1 should be > 0.80, got {:.3}",
        total.f1()
    );
}

fn ner_test_cases() -> Vec<TestCase> {
    vec![
        // NER should catch names
        TestCase {
            text: "Jean Dupont reviewed the merge request yesterday.",
            expected: vec![("person", "Jean Dupont")],
        },
        TestCase {
            text: "Marie Curie discovered radium in Paris.",
            expected: vec![("person", "Marie Curie"), ("location", "Paris")],
        },
        TestCase {
            text: "Contact John Smith at Acme Corp for the contract.",
            expected: vec![("person", "John Smith"), ("organization", "Acme Corp")],
        },
        // NER should NOT flag technical terms
        TestCase {
            text: "The HashMap stores entries indexed by key.",
            expected: vec![],
        },
        TestCase {
            text: "Run cargo build to compile the project.",
            expected: vec![],
        },
        TestCase {
            text: "The OpenAI API returns a JSON response.",
            expected: vec![("organization", "OpenAI")],
        },
        // Combined: regex + NER categories
        TestCase {
            text: "Alice Bob sent an email to alice@example.com from Berlin.",
            expected: vec![
                ("person", "Alice Bob"),
                ("email", "alice@example.com"),
                ("location", "Berlin"),
            ],
        },
    ]
}

fn run_benchmark(
    name: &str,
    filters: &[&dyn ContentFilter],
    cases: &[TestCase],
) -> CategoryMetrics {
    let ctx = default_ctx();
    let mut metrics: std::collections::HashMap<String, CategoryMetrics> =
        std::collections::HashMap::new();
    let mut total = CategoryMetrics::default();
    let mut case_results: Vec<(usize, bool, String)> = Vec::new();

    for (i, case) in cases.iter().enumerate() {
        let mut all_findings = Vec::new();
        for filter in filters {
            all_findings.extend(filter.scan(case.text, &ctx));
        }
        let found_categories: Vec<(&str, String)> = all_findings
            .iter()
            .map(|f| (f.category.as_str(), case.text[f.start..f.end].to_string()))
            .collect();

        let mut matched = vec![false; case.expected.len()];
        let mut finding_matched = vec![false; found_categories.len()];

        for (ei, (exp_cat, exp_text)) in case.expected.iter().enumerate() {
            for (fi, (found_cat, found_text)) in found_categories.iter().enumerate() {
                if finding_matched[fi] {
                    continue;
                }
                if *found_cat == *exp_cat && found_text.contains(exp_text) {
                    matched[ei] = true;
                    finding_matched[fi] = true;
                    let m = metrics.entry(exp_cat.to_string()).or_default();
                    m.true_positives += 1;
                    total.true_positives += 1;
                    break;
                }
            }
        }

        for (ei, m) in matched.iter().enumerate() {
            if !m {
                let cat = case.expected[ei].0;
                let m = metrics.entry(cat.to_string()).or_default();
                m.false_negatives += 1;
                total.false_negatives += 1;
                case_results.push((
                    i,
                    false,
                    format!("FN: expected {}={}", cat, case.expected[ei].1),
                ));
            }
        }

        for (fi, m) in finding_matched.iter().enumerate() {
            if !m {
                let (cat, text) = &found_categories[fi];
                let m = metrics.entry(cat.to_string()).or_default();
                m.false_positives += 1;
                total.false_positives += 1;
                case_results.push((i, false, format!("FP: unexpected {}={}", cat, text)));
            }
        }

        if matched.iter().all(|m| *m)
            && finding_matched
                .iter()
                .all(|m| *m || case.expected.is_empty())
        {
            case_results.push((i, true, "OK".to_string()));
        }
    }

    println!("\n=== {} ===\n", name);
    println!(
        "{:<15} {:>4} {:>4} {:>4} {:>8} {:>8} {:>8}",
        "Category", "TP", "FP", "FN", "Prec", "Recall", "F1"
    );
    println!("{}", "-".repeat(60));

    let mut cats: Vec<_> = metrics.keys().cloned().collect();
    cats.sort();
    for cat in &cats {
        let m = &metrics[cat];
        println!(
            "{:<15} {:>4} {:>4} {:>4} {:>8.3} {:>8.3} {:>8.3}",
            cat,
            m.true_positives,
            m.false_positives,
            m.false_negatives,
            m.precision(),
            m.recall(),
            m.f1()
        );
    }
    println!("{}", "-".repeat(60));
    println!(
        "{:<15} {:>4} {:>4} {:>4} {:>8.3} {:>8.3} {:>8.3}",
        "TOTAL",
        total.true_positives,
        total.false_positives,
        total.false_negatives,
        total.precision(),
        total.recall(),
        total.f1()
    );

    println!("\n--- Failures ---");
    for (i, ok, msg) in &case_results {
        if !ok {
            println!("  Case {}: {}", i, msg);
        }
    }
    let passed = case_results.iter().filter(|(_, ok, _)| *ok).count();
    println!("{}/{} cases fully correct\n", passed, cases.len());

    total
}

#[test]
fn pii_benchmark_regex_plus_ner() {
    let ner_dir = Path::new(&std::env::var("HOME").unwrap_or_default())
        .join(".local/share/navra/models/pii-ner");
    if !ner_dir.join("model.onnx").exists() {
        eprintln!(
            "Skipping NER benchmark: model not found at {}",
            ner_dir.display()
        );
        return;
    }

    let regex_filter = PiiFilter::new();
    let ner_filter = load_ner_filter(&ner_dir).expect("NER filter should load");

    // Regex-only on NER test cases
    let regex_only = run_benchmark(
        "Regex-only (NER test cases)",
        &[&regex_filter],
        &ner_test_cases(),
    );

    // Regex + NER combined
    let combined = run_benchmark(
        "Regex + NER combined",
        &[&regex_filter, &ner_filter],
        &ner_test_cases(),
    );

    println!("=== Comparison ===");
    println!(
        "  Regex-only:  F1={:.3}, precision={:.3}, recall={:.3}",
        regex_only.f1(),
        regex_only.precision(),
        regex_only.recall()
    );
    println!(
        "  Regex + NER: F1={:.3}, precision={:.3}, recall={:.3}",
        combined.f1(),
        combined.precision(),
        combined.recall()
    );

    assert!(
        combined.f1() >= regex_only.f1(),
        "NER should not decrease F1: {:.3} < {:.3}",
        combined.f1(),
        regex_only.f1()
    );
}
