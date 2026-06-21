+++
title = "28. The False Positive Tradeoff"
description = "Aggressive filtering is safe but blocks legitimate content. Permissive filtering is usable but misses PII. navra defaults to deny-wins and lets operators tune the threshold."
weight = 280
template = "docs/page.html"

[extra]
part = "privacy"
toc = true
+++

## What you already know

You know how navra's PrivacyRouter coordinates five detectors to find PII in content. Regex catches structured data, NER catches names, and the short-circuit optimization avoids unnecessary ML inference. But detection is never perfect. This chapter is about what happens when detection is wrong.

## Every detector lies sometimes

No PII detector is perfect. This is not a software deficiency -- it is a mathematical certainty. The problem of determining whether a given string is personally identifiable information is not decidable in the general case. It depends on context, intent, and knowledge that no automated system can fully access.

The best we can do is build systems that are wrong in known, measurable, and manageable ways. That starts with understanding the two directions of error.

## Two kinds of wrong

A PII detector can be wrong in two directions:

**False positive**: the detector flags legitimate content as PII. A regex for phone numbers matches a version string like `1.2.345.6789`. The NER model tags "Rust" as a person's name. A credit card pattern matches a 16-digit account number that passes the Luhn check but is not a credit card.

**False negative**: the detector misses actual PII. A name in an unfamiliar script is not recognized by the NER model. An SSN without hyphens (`123456789`) does not match the formatted pattern. A custom employee ID format is not covered by any built-in pattern.

Both kinds of error have costs:

- False positives break functionality. An agent trying to read a configuration file with version numbers in it gets blocked because the version number looks like a phone number. The developer removes the filter, and now nothing is protected.
- False negatives leak data. An agent reads a file containing customer names and the NER model misses some of them. The names flow through to an untrusted destination.

The fundamental tension: you cannot minimize both error types simultaneously. Reducing false positives (by requiring stronger evidence) increases false negatives (by letting more borderline cases through). Reducing false negatives (by flagging anything that might be PII) increases false positives (by flagging more legitimate content).

## How navra handles the tradeoff

navra makes three design choices to manage this tension:

### 1. Validators reduce false positives at the source

Rather than accepting any regex match, navra validates matches before reporting them. The credit card pattern requires a Luhn checksum. The SSN pattern rejects known-invalid area numbers. The IP address pattern rejects private ranges. The phone number pattern uses context validation to reject matches inside timestamps and version strings.

These validators eliminate the most common false positives without reducing true positive detection. A 16-digit number that passes the Luhn check is almost certainly a real credit card number. A number that fails it is almost certainly not.

### 2. Multiple independent detectors reduce false negatives

No single detector catches everything. By running five detectors with different approaches (three regex, one NER, one ML classification), navra catches PII that any individual detector would miss.

A name that regex cannot detect might be caught by NER. A custom data format that NER does not understand might be caught by the operator's custom patterns. A privacy risk that neither regex nor NER recognizes ("the patient in room 302") might be caught by the privacy classification model.

The detectors are independent -- a false negative in one does not cause a false negative in the others (unless the PII is genuinely outside all detectors' capabilities).

### 3. Configurable thresholds let operators tune the balance

navra does not impose a fixed sensitivity level. The operator configures:

- **Which detectors are active.** A development environment might disable NER to avoid model downloads. A healthcare environment might enable all detectors plus custom medical patterns.
- **The short-circuit threshold.** Higher values mean more detectors run on each request (better coverage, slower). Lower values mean the PrivacyRouter stops earlier (faster, but might miss name-only PII).
- **Per-permission-set policy.** Different agents can have different sensitivity levels. A data analysis agent working with customer records might have stricter filtering than a code generation agent that never handles personal data.
- **The response to findings.** Block the content, redact the PII, log a warning, or pass through. The choice depends on the risk level and the operational context.

## The deny-wins default

navra defaults to deny-wins: if any detector finds PII, the finding counts. The operator must explicitly configure a more permissive policy if they want to allow content that triggers detections.

This is a deliberate choice. In security, false positives are annoying but false negatives are dangerous. A blocked legitimate request can be retried or escalated. A leaked SSN cannot be un-leaked.

The deny-wins default means navra starts restrictive. Operators tune it less restrictive based on their experience:

1. Deploy with defaults.
2. Monitor false positives in the blackbox (tool results that were blocked but look legitimate).
3. Add context validators or custom exclusion patterns for specific false positive categories.
4. Lower thresholds for agents that handle non-sensitive data.

This is a "start strict, relax with evidence" approach. The opposite -- start permissive and tighten after incidents -- means PII leaks happen before protections are in place.

## Common false positive scenarios

Through testing, navra has identified and mitigated several common false positive patterns:

**Version strings as phone numbers.** `1.234.567.8901` matches the phone number regex. The context validator checks whether the "phone number" appears near a period-separated pattern characteristic of version strings, and rejects it.

**Timestamps as credit cards.** `20260621143045` is 14 digits and could match a credit card pattern. The Luhn validator rejects it because timestamps almost never pass the checksum.

**Configuration values as PII.** `port = 5432` does not trigger anything, but `password = hunter2` triggers the password detection pattern (in the SecretFilter, not the PiiFilter). This is intentional -- passwords in configuration files are secrets that should not be exposed.

**Code examples as PII.** Documentation or test files often contain example PII: `555-12-3456` as a sample SSN, `john@example.com` as a sample email. navra's PII filter catches these because it cannot distinguish examples from real data. This is a correct false positive -- the operator should decide whether example PII in tool responses is acceptable.

## Tuning in practice

Here is a concrete tuning workflow for an organization deploying navra:

**Week 1: Deploy with defaults.** All detectors enabled, short-circuit threshold at 5, deny-wins policy. Agents will encounter false positives. This is expected.

**Week 2: Review the blackbox.** Query for tool calls with outcome `denied_pii` or similar privacy-related denials. For each denial, examine the tool result that was blocked. Categorize: was it actual PII, or a false positive?

**Week 3: Add exclusions.** For recurring false positive patterns, add context validators or custom exclusion rules. For example, if version strings in log output consistently trigger phone number detection, add the version-string context validator (navra includes this by default, but custom log formats might need additional patterns).

**Week 4: Adjust per agent.** Agents that handle customer data keep strict defaults. Agents that only generate code can have relaxed thresholds. The per-permission-set configuration means you do not have to choose one sensitivity level for the entire system.

**Ongoing: Monitor metrics.** Watch the Prometheus counters for PII detections by category. A sudden spike in `credit-card` detections from an agent that handles test data might indicate a test database with real card numbers -- a problem in the data pipeline, not in navra's configuration.

The key principle: tuning is iterative and evidence-based. Start strict, collect data, relax with justification. Never start permissive and hope to tighten later.

## Measuring accuracy

navra's adversarial evaluation suite measures detection accuracy across categories:

- **Precision**: Of the items flagged as PII, what fraction actually are PII?
- **Recall**: Of the actual PII in the content, what fraction was flagged?

For structured PII (SSN, credit cards with Luhn), precision is very high (>99%) because the validators eliminate most false positives. Recall is also high because the patterns are unambiguous.

For names (NER-based), precision is moderate (the model sometimes flags non-names) and recall depends on the language and context. English names in formal text have high recall. Names in informal text, code comments, or non-English languages have lower recall.

The operator sees aggregate metrics in the blackbox and Prometheus. If precision drops (too many false positives), they tighten validators or add exclusion patterns. If recall drops (PII leaks detected after the fact), they add custom patterns or lower the short-circuit threshold.

## The human in the loop

Ultimately, the false positive tradeoff is a human decision. navra provides the detection mechanisms, the configuration knobs, and the monitoring data. But deciding "this false positive rate is acceptable for our use case" requires understanding the use case, the data sensitivity, and the organizational risk tolerance.

A healthcare company processing patient records will accept more false positives (blocking legitimate content) to minimize false negatives (leaking patient data). A software development team using agents for code generation will accept more false negatives (names in code comments are low risk) to minimize false positives (agents blocked from reading documentation).

navra does not make this decision for you. It provides the tools to implement whatever decision you make, and the metrics to evaluate whether the decision is working.

## What false positives look like in the blackbox

When the PrivacyRouter flags content and the chokepoint blocks a tool result, the blackbox records the event. An operator investigating false positives can query the blackbox:

```sql
SELECT agent_name, tool_name, tool_args, tool_result, timestamp_ms
FROM blackbox
WHERE outcome = 'denied_content'
ORDER BY timestamp_ms DESC
LIMIT 20;
```

Each record shows exactly what content was blocked and why. The `tool_result` field (truncated to 4 KB) contains enough of the original content to evaluate whether the detection was correct. The `tool_args` field shows what the agent was trying to do.

This queryable audit trail is what makes tuning practical. Without it, operators are guessing. With it, they can make evidence-based decisions about which detections are correct and which are false positives.

## What's next

PII detection is one part of a broader compliance picture. In the final chapter of this part, we map navra's capabilities to specific regulatory requirements: EU AI Act, SOC2, and ISO 42001. The goal is not to claim compliance (that requires an auditor) but to show how navra's technical controls address specific regulatory clauses.
