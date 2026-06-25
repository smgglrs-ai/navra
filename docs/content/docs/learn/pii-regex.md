+++
title = "25. PII Detection with Regex"
description = "Regex-based PII detection is fast and precise for structured patterns like SSNs, credit cards, and email addresses. It is also incomplete: no regex can catch 'John Smith' as PII."
weight = 250
template = "docs/page.html"

[extra]
part = "privacy"
toc = true
+++

## What you already know

You know that navra's content filters scan tool call results for sensitive data. You have seen the security pipeline in the chokepoint, where results pass through filters before reaching the agent. Now we look at the first and fastest detector: regex-based PII scanning.

## Why regex first

When a tool returns content, navra needs to decide whether that content contains personally identifiable information. The fastest way to check is with regular expressions -- compiled patterns that match text in microseconds, even on large inputs.

navra's `PiiFilter` carries a set of compiled patterns, each targeting a specific PII category. When content arrives, each pattern scans the text. If a pattern matches, a finding is recorded with the match position, category, and confidence score.

Regex runs first for two reasons: it is cheap (microseconds per scan) and it is precise for structured data. A Social Security Number always looks like three digits, a hyphen, two digits, a hyphen, four digits. A credit card number is 13-19 digits. An email address has a `@` sign and a domain. These patterns are unambiguous and machine-readable.

## What the patterns catch

navra's PII filter includes patterns for:

**US Social Security Numbers.** The pattern `\b\d{3}-\d{2}-\d{4}\b` matches formatted SSNs. A validator rejects invalid SSNs (area numbers 000, 666, and 900-999 are not issued by the SSA).

**Credit card numbers.** The pattern matches 13-19 digit sequences with optional separators. A Luhn checksum validator rejects random number sequences that happen to be the right length. A context validator checks that the match is not part of structured data like a timestamp or version number.

**Email addresses.** The standard pattern: local part, `@` sign, domain with TLD.

**Phone numbers.** US format (`(555) 123-4567`) and European format (`+33 1 23 45 67 89`), with various separator styles.

**French NIR (social security).** The 15-digit format with a check key validator. France's NIR uses a specific structure: gender, year, month, department, municipality, birth order, check key.

**French SIRET.** 14-digit business registration numbers with a Luhn-like validator. SIRET patterns are checked before credit cards because a valid SIRET has the same length as some credit card formats. The more specific pattern wins.

**EU IBAN.** Country code, check digits, and bank-specific account numbers. A validator checks the IBAN's modular arithmetic (mod 97).

**Passport numbers.** Country-specific formats (the French format: 2 digits, 2 letters, 5 digits).

**IP addresses.** IPv4 addresses with octet validation (each part 0-255). A validator rejects private ranges (192.168.x.x, 10.x.x.x, 127.x.x.x) since those are not personally identifying.

## Validators: beyond pattern matching

A regex match is necessary but not sufficient. The string `123-45-6789` looks like an SSN, but `000-45-6789` is not a valid SSN. The string `4111111111111111` looks like a credit card, but `1234567890123456` fails the Luhn check.

navra attaches optional validators to each pattern:

**Value validators** check the matched string in isolation. The Luhn check sums digits with a specific weighting and verifies the result is divisible by 10. The SSN validator rejects known-invalid area numbers. The IBAN validator performs modular arithmetic on the full number.

**Context validators** check the match against surrounding text. The phone context validator rejects matches that appear inside IP addresses, UUIDs, or version numbers. The credit card context validator rejects matches that appear in structured data like JSON keys, timestamps, or hexadecimal strings.

This two-level validation dramatically reduces false positives. Without it, a regex for "13-19 digits" would flag every long number in every log file and data dump. With Luhn validation and context checking, the filter catches real credit card numbers and ignores everything else.

## PathPiiFilter: detecting PII in file paths

PII does not only appear in content. It can appear in file paths:

```
/home/john.smith/documents/tax_returns/
/data/exports/customers/alice_johnson_ssn.csv
```

navra's `PathPiiFilter` scans tool arguments (specifically, path-valued arguments) for patterns that suggest PII in directory and file names. It looks for email-like patterns in paths, usernames that look like real names, and filename patterns that suggest sensitive documents.

Path-based PII detection is coarser than content detection -- you cannot run a Luhn check on a directory name. But it catches the common case where an agent is trying to access files in a user's home directory or export directory where filenames contain personal information.

## Deduplication

When multiple patterns match the same text span, navra deduplicates. A 14-digit number that matches both the SIRET pattern and the credit card pattern is reported once, under the more specific category. The deduplication rule: if a more specific pattern has already matched this exact byte range, the broader pattern is skipped.

This prevents double-counting in the PrivacyRouter's short-circuit threshold (covered in a later chapter). Five regex findings should mean five distinct pieces of PII, not one piece matched by five overlapping patterns.

## PromptInjectionFilter: detecting manipulation

Beyond PII and secrets, navra's regex layer also includes a `PromptInjectionFilter` that detects common prompt injection patterns in tool responses. If an external tool's output contains text designed to manipulate the LLM -- `<system>` tags, imperative override phrases like "ignore your instructions," or special tokens like `<im_start>` -- the filter flags it.

This is not PII detection, but it uses the same infrastructure: compiled regex patterns, the `ContentFilter` trait, and integration with the PrivacyRouter pipeline. The prompt injection filter runs alongside PII detection and its findings contribute to the overall risk assessment of tool output.

Prompt injection detection through regex is inherently limited (attackers can rephrase), but it catches the most common patterns at near-zero cost. More sophisticated injection detection would require an ML model, which is a possible future addition.

## What regex cannot catch

Regex excels at structured, predictable patterns. It fails completely at unstructured PII:

- **Names.** "John Smith" is PII, but no regex can distinguish a person's name from any other two-word string. "Red Hat" looks the same to a regex as "John Smith."
- **Addresses.** "123 Main Street, Springfield, IL 62701" is PII, but "123" and "Main Street" and "Springfield" are all common words.
- **Medical information.** "Patient has Type 2 diabetes" is sensitive health data, but the words themselves are not PII patterns.
- **Contextual PII.** "The CEO of Acme Corp" is not PII by itself, but combined with other information it can identify a specific person.
- **Obfuscated PII.** "J o h n  S m i t h" or "john [at] example [dot] com" are PII written to evade detection. A human reads them easily; a regex does not.
- **Encoded PII.** Base64-encoded text, ROT13, or URL-encoded strings might contain PII that is invisible to pattern matching on the decoded content.

This is not a failure of navra's regex patterns. It is a fundamental limitation of pattern matching as a technique. Patterns match syntax, not semantics. To detect PII that lacks syntactic markers, you need a system that understands language.

For these categories, navra needs a different approach: machine learning models that understand language, not just patterns. That is the next chapter.

## SecretFilter: a parallel concern

navra's regex-based detection is split into two filters. The PiiFilter handles personally identifiable information (SSNs, credit cards, phone numbers). The SecretFilter handles credentials and secrets:

- **AWS access keys** (`AKIA` prefix followed by 16 uppercase alphanumeric characters)
- **AWS secret keys** (the `secret_access_key` assignment pattern)
- **GitHub personal access tokens** (`ghp_` prefix, 36 characters)
- **GitHub fine-grained tokens** (`github_pat_` prefix, 82 characters)
- **GitLab tokens** (`glpat-` prefix)
- **OpenAI API keys** (`sk-proj-` prefix)
- **Anthropic API keys** (`sk-ant-` prefix)
- **Bearer tokens** in configuration files
- **PEM private keys** (the `-----BEGIN PRIVATE KEY-----` header)
- **Password assignments** (`password = "..."` patterns)
- **Connection strings** with embedded passwords (`postgres://user:pass@host`)
- **Slack webhook URLs**

Secrets and PII are different categories with different risks. A leaked SSN is a privacy violation. A leaked API key is a security breach. Both must be caught, but the response may differ: PII triggers privacy policies (redaction, audit), while secrets trigger security policies (key rotation, access revocation).

Both filters run through the same `ContentFilter` trait and participate in the PrivacyRouter's coordination. The distinction is organizational, not architectural.

## Performance

Regex scanning is fast. navra uses `regex_lite`, a lightweight regex engine that trades some features for smaller binary size and faster compilation. Typical scan time is under 100 microseconds for a 4 KB text block. Since regex runs on every tool call result, this performance matters -- adding milliseconds to every tool call would degrade the agent experience.

The patterns are compiled once at startup and reused for every scan. There is no per-call overhead beyond the text matching itself.

The choice of `regex_lite` over the full `regex` crate is deliberate. navra's patterns do not use advanced features like lookahead or backreferences. `regex_lite` compiles faster, uses less memory, and produces a smaller binary. For PII detection, the simpler engine is the right tradeoff.

## Adding custom patterns

Organizations often have domain-specific PII formats that navra's built-in patterns do not cover. The `CustomPiiFilter` allows operators to define additional regex patterns in configuration:

```toml
[[privacy.custom_patterns]]
category = "employee-id"
pattern = "EMP-\\d{6}"

[[privacy.custom_patterns]]
category = "medical-record"
pattern = "MRN-\\d{8}"
```

Custom patterns participate in the same pipeline as built-in patterns: they are compiled once at startup, run during the regex phase of the PrivacyRouter, and their findings are aggregated with built-in findings for threshold evaluation.

This extensibility is important because PII is domain-specific. A healthcare system's medical record number, a financial institution's account format, or a government agency's case number are all PII in their respective contexts but are not covered by generic patterns. Custom patterns close this gap without requiring code changes.

## What's next

Regex catches structured PII reliably. But the biggest category of PII -- names -- is invisible to regex. In the next chapter, we look at how navra uses ONNX-based named entity recognition to detect names, organizations, and locations in natural language text.
