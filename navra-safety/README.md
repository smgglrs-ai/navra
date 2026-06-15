# navra-safety

PII detection, content safety filters, and pseudonymization for Rust applications.

`navra-safety` provides a pipeline of content filters that detect sensitive data
(secrets, PII, prompt injection) in text. It supports regex-based filters with
zero native dependencies, and optional ML-based classifiers via ONNX Runtime.

## Quick start

```rust
use navra_safety::{FilterPipeline, FilterAction, FilterContext, SecretFilter, PiiFilter};

let mut pipeline = FilterPipeline::new(FilterAction::Redact);
pipeline.add_filter(SecretFilter::new());
pipeline.add_filter(PiiFilter::new());

let ctx = FilterContext {
    agent_name: "my-app",
    operation: "read",
    path: None,
};

let result = pipeline.process("AWS key AKIAIOSFODNN7EXAMPLE, SSN 123-45-6789", &ctx);
assert!(result.unwrap().contains("[REDACTED:"));
```

## What it detects

### Secrets (SecretFilter)
AWS keys, GitHub/GitLab tokens, OpenAI/Anthropic API keys, private keys,
passwords, connection strings, Slack webhooks, bearer tokens.

### PII (PiiFilter)
US SSNs, credit cards (Luhn-validated), phone numbers, emails, French NIR/SIRET,
EU IBANs, passports, EU phone numbers, public IPv4 addresses.

### Path PII (PathPiiFilter)
Usernames in file paths that look like personal names (e.g., `/home/jean.dupont/`).

### Prompt injection (PromptInjectionFilter)
System prompt tags, imperative overrides, markdown image exfiltration,
encoded injection attempts, special LLM tokens.

### Custom patterns
`CustomFilter` and `CustomPiiFilter` for organization-specific patterns.

## Filter actions

- `Pass` -- return content unmodified
- `Redact` -- replace findings with `[REDACTED:category]` markers
- `Pseudonymize` -- replace with consistent pseudonyms (`Person_A`, `Email_A`)
- `Block` -- reject the entire content

## Pseudonymization

Pseudonyms are consistent within a session: the same input always maps to the
same pseudonym. A `PseudonymReverser` can be extracted for authorized
de-pseudonymization (GDPR data subject access).

## ONNX feature

Enable the `onnx` feature for ML-based detection:

```toml
[dependencies]
navra-safety = { version = "0.1", features = ["onnx"] }
```

This adds NER-based entity detection (`NerFilter`) and a privacy-filter model
(`PrivacyFilterModel`) using ONNX Runtime.

## ML classifier integration

Implement the `Classifier` trait to plug in any classification backend:

```rust
use navra_safety::{Classifier, ClassifyOutput, ClassifyError, MlFilter};
use std::sync::Arc;

struct MyClassifier;

impl Classifier for MyClassifier {
    fn classify<'a>(&'a self, text: &'a str)
        -> std::pin::Pin<Box<dyn std::future::Future<
            Output = Result<ClassifyOutput, ClassifyError>
        > + Send + 'a>>
    {
        Box::pin(async move {
            // Your inference logic here
            Ok(ClassifyOutput { labels: vec![] })
        })
    }
}

let filter = MlFilter::new(Arc::new(MyClassifier), 0.5, "ml-unsafe");
```

## License

Apache-2.0
