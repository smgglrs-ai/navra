+++
title = "27. The Privacy Router"
description = "Five detectors, one coordinator. The PrivacyRouter runs cheap regex first, skips expensive ML models when regex found enough, and tracks short-circuit savings with a Prometheus counter."
weight = 270
template = "docs/page.html"

[extra]
part = "privacy"
toc = true
+++

## What you already know

You know navra has two kinds of PII detectors: regex-based filters (fast, good at structured data) and NER models (slower, good at names). Running both on every tool call result gives good coverage, but running a transformer model on every request has a cost: 1-10 milliseconds of CPU time and memory for inference. This chapter covers how the PrivacyRouter coordinates all detectors efficiently.

## Five detectors

The PrivacyRouter manages five independent privacy detectors:

1. **PiiFilter** -- regex patterns for SSNs, credit cards, email, phone numbers, IBANs, IPs, and more. Fast. No dependencies.

2. **PathPiiFilter** -- regex patterns for PII in file paths and directory names. Also fast.

3. **CustomPiiFilter** -- operator-defined regex patterns for domain-specific PII. If your organization has internal employee ID formats or proprietary data patterns, you add them here.

4. **NerFilter** -- ONNX-based named entity recognition for detecting names, organizations, and locations. Requires ONNX Runtime and a model file. Slower.

5. **PrivacyFilterModel** -- ONNX-based classification model that scores entire text blocks for privacy risk. Not a pattern matcher -- it reads the whole text and outputs a privacy risk score. Requires ONNX Runtime and a separate model.

Each detector implements the same `ContentFilter` trait: it takes content text and a filter context, and returns a list of findings with byte positions, categories, and confidence scores.

## The routing logic

The PrivacyRouter does not simply run all five detectors in sequence. It routes content through two phases:

**Phase 1: Cheap detectors (always run).** PiiFilter, PathPiiFilter, and CustomPiiFilter are regex-based. They run in microseconds. The PrivacyRouter always runs these, regardless of results.

**Phase 2: Expensive detectors (conditionally skipped).** NerFilter and PrivacyFilterModel use ONNX inference. They are 100-1000x slower than regex. The PrivacyRouter skips them when:

- The cheap detectors already found enough findings (at or above the short-circuit threshold).
- The content is too short for NER to be useful (under 10 characters).

The short-circuit threshold defaults to 5. If the regex phase finds 5 or more PII findings, the PrivacyRouter skips the expensive ML detectors. The reasoning: if we already know the content contains PII, spending additional time to find *more* PII does not change the outcome. The content will be flagged or redacted either way.

## Short-circuit in code

Here is the core logic from `navra-safety/src/privacy_router.rs`:

```rust
fn scan(&self, content: &str, ctx: &FilterContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Phase 1: cheap regex detectors
    if let Some(ref f) = self.pii_filter {
        findings.extend(f.scan(content, ctx));
    }
    if let Some(ref f) = self.path_pii_filter {
        findings.extend(f.scan(content, ctx));
    }
    if let Some(ref f) = self.custom_pii_filter {
        findings.extend(f.scan(content, ctx));
    }

    // Phase 2: expensive ML detectors
    let skip_expensive = findings.len() >= self.short_circuit_threshold
        || content.len() < MIN_NER_LENGTH;

    if skip_expensive {
        // Log and count the skip
        self.skipped_total.fetch_add(1, Ordering::Relaxed);
    } else {
        if let Some(ref f) = self.ner_filter {
            findings.extend(f.scan(content, ctx));
        }
        if let Some(ref f) = self.privacy_model {
            findings.extend(f.scan(content, ctx));
        }
    }

    findings
}
```

The `skipped_total` counter is an `AtomicU64`. It tracks how many times the expensive detectors were skipped. This counter is exposed as a Prometheus metric, so operators can see how often the short-circuit fires in production.

## Configuration

The PrivacyRouter is configured in `config.toml`:

```toml
[privacy]
regex_pii = true
path_pii = true
ner = true
privacy_model = true
custom_pii = true
short_circuit_threshold = 5
```

Each detector can be enabled or disabled independently. An operator who does not have ONNX Runtime installed can disable `ner` and `privacy_model` and still get regex-based detection. An operator in a high-security environment can set `short_circuit_threshold = 0` to always run all detectors, accepting the performance cost for maximum coverage.

## Builder pattern

The PrivacyRouter uses a builder pattern for construction:

```rust
let router = PrivacyRouter::builder()
    .pii_filter(PiiFilter::new())
    .path_pii_filter(PathPiiFilter::new())
    .ner_filter(ner_model)         // Option<Arc<NerFilter>>
    .privacy_model(privacy_model)  // Option<Arc<PrivacyFilterModel>>
    .short_circuit_threshold(5)
    .build();
```

The builder accepts `Option` values for the ONNX-based detectors. If the model files are not available, the builder skips those detectors. The PrivacyRouter works with any combination of detectors -- all five, just regex, or any subset.

## Why not parallel execution

You might wonder: why not run all five detectors in parallel? Regex is fast enough to finish before the ML models even load the input. Running them in parallel would not save time because the regex phase is not the bottleneck.

More importantly, the short-circuit optimization depends on knowing the regex results *before* deciding whether to run the ML models. If you run everything in parallel, you always pay the cost of ML inference, even when the regex phase would have short-circuited.

The sequential phase-1-then-maybe-phase-2 approach gives you the best latency in the common case (content with obvious PII is caught by regex alone) while still providing ML-based detection for the harder cases (content with names but no structured PII).

## Finding aggregation

The PrivacyRouter returns all findings from all detectors as a flat list. The caller (typically the content filter pipeline in the chokepoint) decides what to do with them:

- **Count above threshold**: block the tool result or redact the PII.
- **Count below threshold**: pass the result through with a warning.
- **Zero findings**: pass through without modification.

The threshold and response policy are configured per permission set, not per detector. This keeps the PrivacyRouter focused on detection and delegates the policy decision to the security pipeline.

## Observability

The PrivacyRouter exposes several metrics:

- `privacy_router_skipped_total`: How many times expensive detectors were skipped due to short-circuit.
- Individual detector metrics (finding counts, latency) are tracked by each detector independently.

These metrics let operators answer practical questions: "Is the short-circuit threshold too low? Are we skipping ML detection too aggressively?" If the skip rate is 95% and the operators are satisfied with detection accuracy, the threshold is working well. If missed PII incidents are reported, the threshold might need to be lowered.

## The design philosophy

The PrivacyRouter embodies a principle that runs through navra's design: *cheap checks first, expensive checks only when needed*.

This same principle applies elsewhere in navra. In the chokepoint pipeline, a simple pause check runs before ACL evaluation. ACL evaluation runs before IFC analysis. Each check is more expensive than the last, and each check can short-circuit the rest.

The PrivacyRouter applies this principle to content analysis. Regex is cheap. NER is expensive. Run regex first. If regex finds enough, skip NER. The operator sees no difference in the final decision (content is flagged either way), but the system runs faster.

This design is particularly important for interactive agents, where tool call latency directly affects the user experience. Adding 10 milliseconds of ML inference to every tool call is noticeable. Adding it only to tool calls where regex found nothing is barely measurable.

## What's next

Every detection system has false positives -- legitimate content that gets flagged as PII. The next chapter covers the false positive tradeoff: how aggressive filtering versus permissive filtering affects usability, and how operators tune the system for their environment.
