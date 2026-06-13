# PII handling (completed 2026-04-25)

### Original gaps (all resolved) ✅

1. ✅ **Fix false positives** — timestamp/UUID negative lookaheads
   in phone and pattern regexes
2. ✅ **Add EU PII patterns** — NIR, IBAN, SIRET/SIREN, EU phone,
   IP addresses, passport numbers
3. ✅ **Filter on memory ingestion** — PII filter runs on
   KnowledgeStore::store and distillation output
4. ✅ **Redact audit logs** — blackbox entries pass through the
   safety pipeline before persistence
5. ✅ **PII as IFC label** — `Confidentiality::Pii` above Sensitive;
   tool results containing PII auto-label; IFC blocks writes to
   non-PII-safe destinations
6. ✅ **Data retention / purge** — `memory_purge_pii` tool,
   configurable retention TTL, PII scan on existing data

### Additional PII work completed ✅

| Feature | Detail |
|---------|--------|
| NER semantic detection | ProtectAI + multilingual XLM-RoBERTa ONNX models for entity recognition beyond regex patterns |
| Pseudonymization | `FilterAction::Pseudonymize` with `PseudonymMap` for reversible replacement (e.g., `Jean Dupont` → `Person_A`) |
| Custom PII patterns | `[[pii_patterns]]` config section for operator-defined PII categories |
| PII in embeddings | Cascade deletion from vector store when source content is purged |
| Model reasoning filter | PII detection on agent text output (model reasoning), not just tool results |
| File path PII detection | `PathPiiFilter` detects PII leaked via file paths (e.g., `/home/jean.dupont/`) |
| Consent tracking | Per-data-subject consent records; `pii_report` tool for GDPR data subject access requests |
| PII model download | `navra pii download` CLI command to fetch NER models (protectai, xlm-roberta) |

### Detection layers

1. **Regex** — US patterns (SSN, credit card, phone, email) + EU
   patterns (NIR, IBAN, SIRET, EU phone, IP, passport) + custom
   `[[pii_patterns]]`
2. **NER** — ProtectAI (English) + XLM-RoBERTa (multilingual) ONNX
   models for semantic entity recognition
3. **File paths** — `PathPiiFilter` detects usernames, personal
   directories, and name patterns in file paths

### Filter actions

| Action | Behavior |
|--------|----------|
| `pass` | Log finding, no modification |
| `redact` | Replace with `[REDACTED:category]` |
| `pseudonymize` | Replace with consistent pseudonym via `PseudonymMap` |
| `block` | Reject the entire response |

### Storage filtering

PII filters run on all persistence paths: memory ingestion,
audit/blackbox logs, distillation output, and vector embeddings
(cascade deletion on purge).

### GDPR tools

| Tool | Purpose |
|------|---------|
| `memory_purge_pii` | Purge all PII for a data subject |
| `memory_forget` | Delete specific memory entries |
| `pii_report` | Generate data subject access report |
| `pii_consent` | Record/query consent status |

---
