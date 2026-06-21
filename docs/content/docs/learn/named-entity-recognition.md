+++
title = "26. Named Entity Recognition"
description = "ONNX-based NER detects names, organizations, and locations that no regex can catch. A transformer model classifies each token using BIO tagging. Better than regex for names, but slower."
weight = 260
template = "docs/page.html"

[extra]
part = "privacy"
toc = true
+++

## What you already know

You know that regex-based PII detection catches structured patterns -- SSNs, credit cards, email addresses -- quickly and reliably. But regex cannot catch names. "Alice Johnson" looks like any other pair of words to a regex engine. This chapter covers how navra uses machine learning to detect names and other unstructured PII.

## The problem: names are not patterns

Names are the most common type of PII and the hardest to detect with rules. Consider:

- "John Smith" -- common English name
- "Khadija bint Khuwaylid" -- Arabic patronymic name
- "Kim" -- could be a first name, a surname, or a common English word
- "Dr. Maria Garcia-Lopez" -- title, first name, hyphenated surname
- "LeBron" -- single name that identifies a specific person

No regex can cover all name formats across all languages. Even a dictionary of known names fails: new names appear constantly, and common words overlap with names ("Rose," "Grace," "Hunter," "Mason").

Named Entity Recognition (NER) is the NLP technique that solves this. A NER model reads text token by token and classifies each token into categories: person, organization, location, or none.

## How NER works: BIO tagging

NER models use BIO (Beginning, Inside, Outside) tagging. Each token gets a label:

- **B-PER**: Beginning of a person name
- **I-PER**: Inside (continuation of) a person name
- **B-ORG**: Beginning of an organization name
- **I-ORG**: Inside an organization name
- **B-LOC**: Beginning of a location
- **I-LOC**: Inside a location
- **O**: Not an entity (outside)

Given the text "Alice Johnson works at Red Hat in Raleigh," the model produces:

```
Alice    -> B-PER   (start of person name)
Johnson  -> I-PER   (continuation of person name)
works    -> O       (not an entity)
at       -> O
Red      -> B-ORG   (start of organization)
Hat      -> I-ORG   (continuation of organization)
in       -> O
Raleigh  -> B-LOC   (start of location)
```

The B/I distinction matters for multi-word entities. Without it, "Alice Johnson Red Hat" would be ambiguous -- is it one four-word entity or multiple entities? The B prefix marks where each new entity begins.

## The transformer model

navra's NER filter uses a transformer model exported to ONNX format. Transformers are the architecture behind GPT, BERT, and modern language models. For NER, a small transformer (tens of megabytes, not gigabytes) is sufficient.

The model processes text in three steps:

**Tokenization.** The input text is split into tokens -- roughly word-pieces. "Unbelievable" might become ["un", "##believ", "##able"]. The tokenizer uses a vocabulary learned during training.

**Encoding.** The tokens are converted to numbers (token IDs) and passed through the transformer layers. Each layer reads all tokens simultaneously (the "attention" mechanism) and produces a contextual representation for each token. The representation of "Alice" depends on the words around it -- the same word "Alice" in "Alice in Wonderland" and "Alice Johnson, VP of Engineering" gets different representations.

**Classification.** A final layer maps each token's representation to a BIO label. The model outputs probabilities for each label, and the highest probability wins.

## Why ONNX

ONNX (Open Neural Network Exchange) is a format for exporting trained models from frameworks like PyTorch or TensorFlow into a portable, framework-independent representation. navra uses the `ort` crate to run ONNX models directly, without requiring Python or a separate inference server.

This matters for deployment. navra is a single Rust binary. It does not require a Python runtime, a model server, or a GPU. The NER model runs on CPU using ONNX Runtime's optimized inference engine. On a modern CPU, inference takes 1-10 milliseconds per text block, depending on length.

## navra's NerFilter

The `NerFilter` in `navra-safety` wraps the ONNX model with navra's `ContentFilter` interface:

1. Receive content text from the pipeline.
2. Tokenize the text using the model's tokenizer.
3. Run inference to get BIO labels for each token.
4. Group consecutive B-/I- tokens into entity spans.
5. Return findings with the entity category (person, organization, location), byte positions, and confidence scores.

The filter only runs when the `onnx` feature is enabled and the model file is present. If ONNX Runtime is not installed or the model is missing, the filter is skipped gracefully -- navra logs a warning and continues with regex-only detection.

## NER vs. regex: tradeoffs

| | Regex | NER |
|---|---|---|
| **Speed** | Microseconds | Milliseconds |
| **Structured PII** (SSN, CC) | Excellent | Poor (not trained for this) |
| **Names** | Cannot detect | Good |
| **Organizations** | Cannot detect | Good |
| **Locations** | Cannot detect | Good |
| **False positives** | Low (with validators) | Moderate (context-dependent) |
| **Dependencies** | None | ONNX Runtime + model file |
| **Resource usage** | Negligible | ~50 MB RAM for model |

The two detectors complement each other. Regex catches what NER misses (structured patterns with checksum validation) and NER catches what regex misses (unstructured names and organizations). Running both gives better coverage than either alone.

## Confidence scores

The ONNX model outputs a probability distribution over BIO labels for each token. The highest probability becomes the label, and its value becomes the confidence score. A confidence of 0.99 means the model is very sure; 0.55 means it is barely above chance.

navra uses confidence scores in two ways:

**Filtering low-confidence findings.** The NerFilter has a configurable minimum confidence threshold. Findings below the threshold are discarded. This reduces false positives from ambiguous tokens ("Rose" as a name vs. a flower, "Chase" as a name vs. a bank vs. a verb).

**Informing the PrivacyRouter.** When the PrivacyRouter aggregates findings from all detectors, higher-confidence findings carry more weight in the overall assessment. A regex match for a valid SSN (confidence 1.0) combined with a low-confidence NER name (confidence 0.6) might not trigger the same response as a high-confidence NER match (0.95).

In practice, most NER findings in formal text (emails, reports, documents) have high confidence. Findings in code comments, log output, and mixed-language text tend to have lower confidence. The threshold lets operators balance precision against recall for their specific workload.

## Limitations of NER

NER models have real limitations:

**Training data bias.** The model performs best on text similar to its training data. If it was trained primarily on English news articles, it may miss names in other languages, informal text, or domain-specific contexts.

**Ambiguity.** "Washington" could be a person (George Washington), a location (Washington, D.C.), or an organization (the Washington Post). The model uses context to disambiguate, but context is not always sufficient.

**Adversarial robustness.** An attacker who knows the model exists can craft inputs to evade detection. Inserting zero-width unicode characters between letters ("J​ohn S​mith") might split the token in a way that prevents the model from recognizing the name. navra's regex filters catch some of these evasion techniques, but not all.

**Single-token names.** Very short names ("Li," "Wu," "Kim") are hard for the model to distinguish from common words. The model's confidence score is typically lower for these, which means the PrivacyRouter may not flag them depending on the configured threshold.

**Multilingual text.** A document that mixes English and French, or English and Chinese, may confuse the model at language boundaries. The tokenizer was trained on a specific distribution of languages, and code-switched text falls outside that distribution.

## Graceful degradation

navra is designed to work with or without NER. If ONNX Runtime is not installed (the `onnx` feature is not compiled in, or the shared library is missing), NER is silently disabled. The PiiFilter (regex) still runs. The operator sees a log message at startup:

```
WARN navra_safety: NER model not available, falling back to regex-only PII detection
```

This is important for deployment flexibility. A developer running navra on a laptop may not have ONNX Runtime. A production deployment on a server can install it for better detection. navra adapts to the environment rather than requiring a specific dependency stack.

The same applies to the privacy classification model. Each ONNX-based detector is independently optional. The PrivacyRouter checks which detectors were successfully initialized and routes content accordingly.

## What's next

navra does not run regex and NER as independent, uncoordinated checks. The PrivacyRouter coordinates five different detectors, routes content to the appropriate ones, and short-circuits expensive detectors when cheap ones have found enough. That coordination logic is the subject of the next chapter.
