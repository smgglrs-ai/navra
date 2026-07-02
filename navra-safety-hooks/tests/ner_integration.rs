//! Integration tests for NER-based PII detection with sfermion/bert-pii-detector-onnx.
//!
//! These tests require the model to be downloaded first:
//!   navra pii download
//!
//! Run with:
//!   ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p navra-safety -- --ignored

use navra_safety_hooks::safety::ContentFilter;
use navra_safety_hooks::safety::{FilterContext, NerFilter, default_pii_ner_model_dir};

fn model_dir() -> std::path::PathBuf {
    default_pii_ner_model_dir()
}

fn load_filter() -> NerFilter {
    NerFilter::load_from_dir(&model_dir())
        .expect("PII NER model not installed — run 'navra pii download' first")
}

fn ctx() -> FilterContext<'static> {
    FilterContext {
        agent_name: "test",
        operation: "read",
        path: Some("/test"),
    }
}

#[test]
fn ner_debug_thresholds() {
    let filter = NerFilter::load_from_dir(&model_dir())
        .expect("model not installed")
        .with_confidence_threshold(0.01);
    let texts = [
        "My name is Jean Dupont",
        "Contact John Smith at john.smith@gmail.com",
        "The patient Marie-Claire Dubois was admitted",
        "His passport is AB1234567",
    ];
    for text in texts {
        let findings = filter.scan(text, &ctx());
        eprintln!("Text: {text}");
        for f in &findings {
            eprintln!(
                "  → {} (confidence: {:.4}, {}..{})",
                f.category, f.confidence, f.start, f.end
            );
        }
        if findings.is_empty() {
            eprintln!("  → (no findings even at 0.01 threshold)");
        }
        eprintln!();
    }
}

#[test]
fn ner_detects_person_names() {
    let filter = NerFilter::load_from_dir(&model_dir())
        .expect("model not installed")
        .with_confidence_threshold(0.3);
    let findings = filter.scan("My name is Jean Dupont", &ctx());
    let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(
        categories
            .iter()
            .any(|c| c == &"person" || c == &"username"),
        "Expected person/username category in findings: {categories:?}"
    );
}

#[test]
fn ner_detects_location() {
    let filter = load_filter();
    let findings = filter.scan("I live at 15 rue de Rivoli, 75001 Paris", &ctx());
    let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(
        categories.contains(&"location"),
        "Expected 'location' category in findings: {categories:?}"
    );
}

#[test]
fn ner_detects_organization() {
    let filter = load_filter();
    let findings = filter.scan("She works at Red Hat in Raleigh", &ctx());
    let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(
        categories.contains(&"organization"),
        "Expected 'organization' category in findings: {categories:?}"
    );
}

#[test]
fn ner_detects_multiple_entities() {
    let filter = load_filter();
    let findings = filter.scan("Jean Dupont works at Airbus in Toulouse", &ctx());
    let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(
        categories.contains(&"person"),
        "Expected 'person' in findings: {categories:?}"
    );
    assert!(
        categories.contains(&"organization") || categories.contains(&"location"),
        "Expected 'organization' or 'location' in findings: {categories:?}"
    );
}

#[test]
fn ner_no_pii_in_technical_text() {
    let filter = load_filter();
    let findings = filter.scan(
        "No PII in this technical document about Rust programming",
        &ctx(),
    );
    assert!(
        findings.is_empty(),
        "Expected no findings in technical text, got: {findings:?}"
    );
}
