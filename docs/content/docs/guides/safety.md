+++
title = "Content Safety"
description = "Configure content safety filters, PII detection, canary tokens, and ML classifiers."
weight = 35

[extra]
toc = true
+++

Navra filters every tool response (outbound) and write-path argument
(inbound) through a content safety pipeline. The pipeline runs regex
filters first, then optional ML classifiers, and applies an action
(pass, redact, pseudonymize, or block) to any findings. This guide
covers how to choose a safety profile, extend it with custom patterns,
and layer in ML-based detection.

## Safety profiles

Each permission set has a `safety` field that selects a preset filter
pipeline. The default is `"standard"`.

```toml
[permissions.dev]
safety = "standard"
```

| Profile | Action | Filters | Use case |
|---------|--------|---------|----------|
| `standard` | Redact | Secrets, PII, path-PII, SSRF, exfil, prompt injection | General-purpose protection. Replaces sensitive spans with `[REDACTED:category]` markers. |
| `secrets-only` | Redact | Secrets only | When you need secret detection but PII filtering is too aggressive (e.g., code-heavy workflows). |
| `pseudonymize` | Pseudonymize | Secrets, PII, path-PII, SSRF, exfil, prompt injection | GDPR-oriented workflows where data must remain usable for analysis but de-identified. |
| `block` | Block | Secrets, PII, path-PII, SSRF, exfil, prompt injection | Zero-tolerance environments. Any finding blocks the entire response. |
| `multi-label` | Block | All regex filters + multi-label ML classifier | When you have a classification model (e.g., Granite Guardian) and need per-category thresholds. |
| `guardian` | Redact | All regex filters + ML classifier slot | Granite Guardian HAP model for hate/abuse/profanity detection, with regex redaction as fallback. |
| `guardian-deep` | Redact | All regex filters + ML classifier slot | Same as `guardian` but intended for deeper analysis passes. |
| `none` | Pass | None | Disable all content filtering. Only use for trusted, local-only setups. |

### Choosing a profile

- **Development workstations**: `standard` is a safe default. It
  catches leaked secrets and PII without blocking normal code output.
- **Regulated environments** (HIPAA, SOC2, GDPR): use `pseudonymize`
  or `block` depending on whether filtered output must remain useful
  or must be withheld entirely.
- **ML-augmented safety**: use `guardian` or `multi-label` when you
  have a classification model loaded. These profiles add an async ML
  pass after the regex filters.
- **Minimal overhead**: `secrets-only` skips PII patterns (SSN, email,
  phone, credit card) and only catches API keys, private keys,
  passwords, and connection strings.

## Filter actions

Every finding from the pipeline is handled by one of four actions:

| Action | Behavior | Example |
|--------|----------|---------|
| **Pass** | Content returned unmodified | `AKIAIOSFODNN7EXAMPLE` |
| **Redact** | Sensitive spans replaced with category markers | `[REDACTED:aws-key]` |
| **Pseudonymize** | Sensitive spans replaced with consistent pseudonyms | `Person_A`, `Location_A` |
| **Block** | Entire response rejected with an error | `"Content blocked by security policy"` |

The action is determined by the safety profile. Custom patterns and
ML filters inherit the pipeline's action.

## Built-in filters

All profiles except `none` and `secrets-only` include these filters:

### Secret detection

Detects API keys, tokens, private keys, passwords, and connection
strings with high-confidence regex patterns:

- AWS access key IDs (`AKIA...`) and secret access keys
- GitHub personal access tokens (`ghp_...`) and fine-grained tokens (`github_pat_...`)
- GitLab tokens (`glpat-...`)
- OpenAI (`sk-proj-...`), Anthropic (`sk-ant-...`), and generic `sk-` API keys
- Bearer tokens and authorization headers
- PEM private keys (RSA, EC, DSA, OpenSSH)
- Password assignments in config files
- Database connection strings (Postgres, MySQL, MongoDB, Redis)
- Slack webhook URLs

### PII detection

Detects personally identifiable information with validated patterns
(see [PII Detection with Regex](@/docs/learn/pii-regex.md) for design rationale):

- US Social Security numbers (with SSA rule validation)
- Credit card numbers (with Luhn checksum validation)
- US and EU phone numbers (with false-positive suppression for timestamps and UUIDs)
- Email addresses
- French NIR social security numbers (with mod-97 checksum)
- French SIRET business identifiers (with Luhn validation)
- EU IBAN numbers (with mod-97 validation)
- Passport numbers
- Public IPv4 addresses (private/loopback ranges excluded)

### Path PII detection

Detects real names in file paths. Catches `first.last` and hyphenated
name patterns in `/home/`, `/Users/`, and `C:\Users\` paths while
skipping system accounts (root, www-data, deploy, etc.) and generic
single-word usernames.

### Prompt injection detection

Detects common injection patterns in tool responses:

- System/instruction tags (`<system>`, `<im_start>`, etc.)
- Imperative override phrases ("ignore previous instructions")
- Markdown image exfiltration attempts
- Base64/eval obfuscation
- Special LLM token sequences (`<|im_start|>`, `<|endoftext|>`)

### Additional filters

- **SSRF detection**: catches internal URL patterns that could be used
  for server-side request forgery.
- **Exfiltration detection**: identifies data exfiltration attempts
  through encoded payloads and suspicious URL patterns.
- **Context poisoning detection**: catches attempts to inject false
  context into tool responses.
- **Tiered injection detection**: multi-level prompt injection
  detection with severity scoring.

## Custom regex patterns

Add organization-specific patterns to any permission set with
`safety_patterns`. These patterns are treated as general safety
findings (not PII) and inherit the pipeline's action.

```toml
[[permissions.dev.safety_patterns]]
category = "internal-url"
pattern = "https?://internal\\.example\\.com/.*"

[[permissions.dev.safety_patterns]]
category = "project-secret"
pattern = "PROJ-SECRET-[A-Za-z0-9]{32}"
```

| Field | Type | Description |
|-------|------|-------------|
| `category` | string | Finding category name (appears in `[REDACTED:category]` markers) |
| `pattern` | string | Regex pattern. Invalid patterns are logged and skipped at startup. |

## Custom PII patterns

Define organization-specific PII patterns in the global
`[[pii_patterns]]` section. Unlike `safety_patterns`, categories
defined here are **treated as PII for IFC labeling** -- they trigger
taint elevation and stricter retention policies.

```toml
[[pii_patterns]]
name = "employee-id"
regex = "\\bEMP-\\d{6}\\b"
category = "employee-id"

[[pii_patterns]]
name = "badge-number"
regex = "\\bBDG[A-Z]\\d{4}\\b"
category = "badge"
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable name (used in error messages) |
| `regex` | string | Regex pattern. Startup fails if invalid. |
| `category` | string | PII category name. Registered globally so IFC recognizes it. |

Custom PII filters are added to all profiles that use content
filtering (`standard`, `guardian`, `guardian-deep`, `block`,
`multi-label`). They are not added to `secrets-only`,
`pseudonymize`, or `none`.

## Canary tokens

Canary tokens are tripwire strings planted in sensitive data stores.
If one appears in a tool response, it proves the agent accessed
data it should not have. Canary findings are categorized as
`canary:<name>` and handled by the pipeline's action.

```toml
[[canary_tokens]]
name = "db-password-canary"
value = "CANARY_xK9mP2qR7vL4nQ8"

[[canary_tokens]]
name = "secret-format"
value = "TRAP-[A-Z0-9]{8}"
is_regex = true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | -- | Canary identifier (appears in `canary:<name>` category) |
| `value` | string | -- | Exact string or regex pattern to detect |
| `is_regex` | bool | `false` | Interpret `value` as a regex pattern |

Exact matches have confidence 1.0; regex matches have confidence
0.95. Canary tokens are added to `standard`, `guardian`,
`guardian-deep`, `block`, `multi-label`, and `pseudonymize`
profiles. They are not added to `none` or `secrets-only`.

Tips for effective canary placement:

- Plant unique, random strings in database credential files, internal
  wikis, and HR documents.
- Use the `block` profile to immediately halt any agent that triggers
  a canary.
- Canary detections appear in the audit blackbox with the
  `canary:<name>` category for post-incident review.

## ML safety filters

### Granite Guardian HAP

The `guardian` and `guardian-deep` profiles accept an ONNX
classification model for hate/abuse/profanity (HAP) detection. The
model runs as an async pass after regex filters.

**1. Define the model in config:**

```toml
[models.guardian-hap]
task = "classification"
labels = ["safe", "unsafe"]
threshold = 0.5
```

**2. Download the model:**

```bash
navra model pull guardian-hap
```

**3. Set the safety profile:**

```toml
[permissions.dev]
safety = "guardian"
```

The ML filter is fail-closed: if inference fails, the content is
blocked with an `inference_failure` finding at confidence 1.0.

### Multi-label classification

The `multi-label` profile supports models that emit per-category
scores (e.g., harm, jailbreak, PII, refusal). Configure per-category
thresholds to control which categories trigger blocking:

```toml
[permissions.regulated]
safety = "multi-label"

[permissions.regulated.safety_thresholds]
harm = 0.7
jailbreak = 0.9
pii = 0.5
refusal = 0.8
```

Categories are checked in severity order: Block > Redact > Pass. The
highest-severity triggered action wins. Categories not listed in
`safety_thresholds` are ignored unless a fallback threshold is set
programmatically.

## PII NER models

For semantic PII detection beyond regex (e.g., "John Smith lives in
Paris"), navra supports ONNX-based Named Entity Recognition models
(see [Named Entity Recognition](@/docs/learn/named-entity-recognition.md)
for how NER complements regex). These require the `onnx` feature
flag at build time.

### Download and install

```bash
# English-only (ProtectAI/bert-base-NER-onnx)
navra pii download

# Multilingual (XLM-RoBERTa -- French, German, Spanish, Italian, etc.)
navra pii download --multilingual
```

Models are stored in:

| Model | Path |
|-------|------|
| English NER | `~/.local/share/navra/models/pii-ner/` |
| Multilingual NER | `~/.local/share/navra/models/pii-ner-multilingual/` |
| Privacy filter | `~/.local/share/navra/models/openai-privacy-filter/` |

Override the default paths in config:

```toml
[server]
pii_model_path = "~/.local/share/navra/models/pii-ner"
pii_multilingual_model_path = "~/.local/share/navra/models/pii-ner-multilingual"
```

### Check model status

```bash
navra pii status
```

### Supported entity types

NER models detect entities that regex cannot catch:

| Source model | Entity types |
|-------------|-------------|
| ProtectAI/bert-base-NER | Person, Location, Organization, Misc |
| sfermion/bert-pii-detector | Given name, surname, street, city, state, country, passport, ID card, driver license, social number, IP, date, time, username, password, sex |
| gravitee/bert-small-pii | Date/time, email, phone, credit card, IP/MAC address, IBAN, SSN, bank number, driver license, passport, license plate, IMEI, coordinates |
| Nemotron-PII family | First/last/middle name, address components, date, password, PIN, API key, cookie, email, phone, SSN, credit card, company name, vehicle ID |

NER filters are added to `standard`, `guardian`, `guardian-deep`,
`block`, and `multi-label` profiles when a model is loaded.

### Privacy filter model

The OpenAI privacy-filter is a sparse MoE token classifier that
detects 8 PII categories (account number, address, date, email,
person, phone, URL, secret) using BIOES tagging. It complements
regex and NER with categories that are hard to catch with patterns.

The privacy filter is loaded from
`~/.local/share/navra/models/openai-privacy-filter/` and added to
the same profiles as the NER filter.

## Pseudonymization

The `pseudonymize` profile replaces PII with consistent pseudonyms
within a session. The same real value always maps to the same
pseudonym, preserving referential integrity.

### How it works

Each PII category has a prefix. Within each category, findings are
assigned letters (A, B, C, ..., Z, AA, AB, ...):

| Category | Example | Pseudonym |
|----------|---------|-----------|
| Person | "Jean Dupont" | `Person_A` |
| Location | "Paris" | `Location_A` |
| Email | "user@example.com" | `Email_A` |
| Phone | "+33 1 23 45 67 89" | `Phone_A` |
| SSN/NIR | "123-45-6789" | `ID_A` |
| Credit card/IBAN | "4111..." | `Account_A` |
| IP address | "203.0.113.42" | `Address_A` |
| Organization | "Acme Corp" | `Organization_A` |
| Other | anything else | `Item_A` |

### Reversibility

The pseudonym map supports authorized de-pseudonymization through a
separate `PseudonymReverser` object. The reverser is extracted from
the map and should only be passed to GDPR audit tools -- never to
the agent process. This separation ensures the forward-mapping
process cannot de-pseudonymize without explicit authorization
(GDPR Article 32).

### GDPR considerations

Pseudonymized data is still personal data under GDPR Article 4(5)
because it is reversible with the key. The safety pipeline does
**not** declassify pseudonymized content -- the IFC confidentiality
label remains at `Pii`. Only full redaction (where all findings are
successfully replaced with `[REDACTED:...]` markers) can trigger
declassification from `Pii` to `Sensitive`.

## Storage filtering

PII filtering is applied at multiple storage boundaries to prevent
sensitive data from persisting in navra's data stores.

### Memory module

The memory module runs content through a PII filter pipeline before
storing knowledge entries. Configure the filter profile in
`[modules.memory]`:

```toml
[modules.memory]
pii_filter = "standard"         # "standard", "secrets-only", or "none"
pii_retention_days = 30         # stricter TTL for PII-flagged entries
```

When the filter is set to `block` mode and a finding is detected, the
content is replaced with `[content blocked by PII filter]` and stored
as a placeholder.

### Audit blackbox

The audit blackbox (flight recorder) can optionally sanitize
`tool_args` and `tool_result` fields before writing them to the
append-only SQLite database. When a PII filter is attached, every
recorded entry has its arguments and results run through the filter
pipeline.

The blackbox is always on and append-only -- there is no configuration
to disable it. The PII filter for the blackbox is configured
programmatically during server setup.

### Distillation

When `auto_distill = true` in `[modules.memory]`, facts distilled
from conversations on session end pass through the same PII filter
before being stored as knowledge entries.

### Vector store (RAG)

Documents ingested into the RAG vector store are chunked and embedded.
The PII filter runs on each chunk before embedding and storage,
ensuring that vector representations do not encode sensitive data.

## Metrics and compliance

The safety pipeline tracks PII detection metrics for GDPR DPIA
reporting (Article 35):

- **total_scans**: number of filter pipeline invocations
- **pii_detected**: number of PII findings across all scans
- **pii_redacted**: number of PII findings that were redacted or pseudonymized
- **pii_blocked**: number of PII findings that caused content blocking
- **by_category**: per-category PII detection counts (email, phone, ssn, etc.)

These counters are thread-safe and can be queried at runtime for
compliance dashboards.

## Example: full safety configuration

```toml
[server]
pii_model_path = "~/.local/share/navra/models/pii-ner"

# Global PII patterns (treated as PII for IFC)
[[pii_patterns]]
name = "employee-id"
regex = "\\bEMP-\\d{6}\\b"
category = "employee-id"

# Canary tokens
[[canary_tokens]]
name = "hr-database-canary"
value = "CANARY_xK9mP2qR7vL4nQ8"

[[canary_tokens]]
name = "secret-format"
value = "TRAP-[A-Z0-9]{8}"
is_regex = true

# ML safety model
[models.guardian-hap]
task = "classification"
labels = ["safe", "unsafe"]
threshold = 0.5

# Permission set with full safety stack
[permissions.regulated]
safety = "guardian"
compliance = ["SOC2-CC6.1", "HIPAA-164.312"]

[[permissions.regulated.safety_patterns]]
category = "internal-url"
pattern = "https?://internal\\.example\\.com/.*"

# Memory with PII filtering
[modules.memory]
pii_filter = "standard"
pii_retention_days = 30
```
