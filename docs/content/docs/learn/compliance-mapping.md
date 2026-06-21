+++
title = "29. Compliance Mapping"
description = "How navra's blackbox, IFC, and privacy controls map to EU AI Act Article 14, SOC2 CC6.1, and ISO 42001. Not a compliance claim — a technical mapping of controls to requirements."
weight = 290
template = "docs/page.html"

[extra]
part = "privacy"
toc = true
+++

## What you already know

You have seen navra's full stack: ACLs and capability tokens for authorization, IFC for information flow control, the PrivacyRouter for PII detection, and the blackbox for audit recording. These are technical controls. This chapter maps them to regulatory requirements -- not to claim that navra makes you compliant (that requires an auditor and organizational processes), but to show how specific technical controls address specific regulatory clauses.

## A disclaimer first

This chapter is written by engineers, not lawyers. It maps technical controls to regulatory language. It does not constitute legal advice, and it does not represent a compliance certification. Organizations should engage qualified legal and compliance professionals to evaluate their specific regulatory obligations.

With that said, the mapping is valuable. It saves compliance teams time by showing exactly which navra features address which requirements, and it highlights the gaps that the organization must fill with policies and processes.

## Why mapping matters

When an organization deploys AI agents, three questions come up quickly:

1. "Can we prove what the agent did?" (Audit)
2. "Can a human intervene when the agent goes wrong?" (Oversight)
3. "Are we protecting personal data?" (Privacy)

Different regulations phrase these questions differently, but the underlying concerns are the same. navra's technical controls were designed with these concerns in mind. The mapping makes that explicit.

## EU AI Act: Article 14 (Human Oversight)

The EU AI Act requires that high-risk AI systems have human oversight measures. Article 14 specifically requires:

> "High-risk AI systems shall be designed and developed in such a way [...] that they can be effectively overseen by natural persons during the period in which the AI system is in use."

navra provides three mechanisms for human oversight:

**The pause button.** navra's global pause state (controlled from the system tray) immediately stops all tool execution. When an operator sees an agent behaving unexpectedly, one click halts all activity. This is the simplest form of human intervention -- an emergency stop.

**Approval-required tool policies.** Individual tools can be configured to require human approval before execution. When an agent calls a tool with `Approve` policy, navra blocks the call and returns "Approval required." The operator reviews the request and grants or denies it. This is pre-execution oversight -- the human decides before the action happens.

**The blackbox.** The always-on audit trail provides post-execution oversight. An operator can review what agents did, when, with what arguments, and with what results. The hash chain ensures the record has not been tampered with. This is retrospective oversight -- the human can understand what happened after the fact.

The AI Act does not prescribe specific technical implementations. It requires that oversight mechanisms exist. navra's mechanisms map to the requirement, but compliance depends on how the organization configures and uses them.

## SOC2 CC6.1: Logical Access Controls

SOC2 Trust Services Criteria CC6.1 requires:

> "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events."

navra's access control stack maps to this requirement at multiple levels:

**Capability tokens** implement least-privilege access. Each token grants specific tools, a specific ring (privilege level), and a specific expiry. An agent cannot access tools outside its token's grants. The attenuation property (formally proven) ensures that delegated tokens never exceed parent privileges.

**ACL rules** provide deny-wins evaluation. If any rule denies access, the request is blocked regardless of allow rules. This is fail-closed by construction -- proven by four exhaustive Kani proofs.

**Path ACLs** restrict filesystem access per agent. Even if a tool grants file access, the ACL can restrict it to specific directories. This maps to "access over protected information assets."

**Session isolation** ensures that one agent's session state cannot affect another's. This is verified by the TLA+ SessionIsolation specification.

For SOC2 CC6.1, the technical controls exist. The compliance question is whether the organization has configured them appropriately -- a technology control is only as good as its configuration and the operational process around it.

## SOC2 CC7.2: System Monitoring

SOC2 CC7.2 requires monitoring to detect anomalies and security events. navra contributes through:

**Blackbox recording.** Every tool call is recorded with agent identity, tool name, arguments, result, and outcome. The blackbox is always on -- there is no opt-out. This provides the raw data for anomaly detection.

**Hash chain integrity.** The SHA-256 hash chain lets auditors verify that the record has not been tampered with. The `verify_chain` method walks the chain from entry 1 and reports the first broken link.

**Prometheus metrics.** navra exports metrics for tool calls, denials, rate limit hits, IFC violations, and PrivacyRouter short-circuits. These metrics feed into existing monitoring systems (Grafana, Datadog, etc.) for real-time alerting.

## ISO 42001: AI Management System

ISO 42001 (published 2023) is the first international standard for AI management systems. It requires organizations to manage AI risks, maintain documentation, and keep records of AI system decisions.

**Clause 6.1.4 (AI risk treatment)** requires identification and treatment of AI risks. navra's IFC system directly treats the risk of data exfiltration (untrusted agents reading confidential data and writing it to public destinations). The PrivacyRouter treats the risk of PII exposure. The blackbox treats the risk of unaccountable AI actions.

**Clause 7.5 (Documented information)** requires records of AI system operations. The blackbox provides this automatically -- every tool call, every argument, every result, every outcome. The hash chain provides integrity. The SQLite storage provides durability.

**Clause 9.1 (Monitoring, measurement, analysis)** requires ongoing monitoring of AI system performance and compliance. Prometheus metrics and blackbox queries provide the data. The PrivacyRouter's skip counter and detector metrics provide privacy-specific monitoring.

## The hash chain: tamper detection without infrastructure

Many audit systems depend on external infrastructure: a SIEM, a log aggregation service, an immutable storage backend. navra's hash chain provides tamper detection without any of these.

Each blackbox entry includes the SHA-256 hash of the previous entry. The first entry chains from a zero hash. To verify the chain, walk from entry 1 and recompute each hash. If the recomputed hash does not match the stored hash at any point, entries at or after that point have been modified.

The hash chain does not prevent tampering. An administrator with database access can modify entries. But they cannot modify entries without breaking the chain -- and a broken chain is detectable. This is a stronger guarantee than plain logs, which can be silently modified without any evidence of tampering.

For full tamper-proof guarantees, the hash chain can be anchored to an external timestamping service or blockchain. navra does not do this out of the box, but the chain is compatible with RFC 3161 timestamping.

## GDPR: Right to explanation

GDPR Article 22 gives individuals the right not to be subject to decisions based solely on automated processing. When an AI agent takes an action that affects a person, the organization may need to explain why that action was taken.

navra's blackbox provides the factual record: "Agent X called tool Y with arguments Z at time T, and the result was W." This is the *what*, not the *why*. The *why* is in the LLM's reasoning, which navra does not record (it operates at the tool call level, below the model's decision-making).

However, the blackbox record is valuable for explanation. If a customer asks "why was my application rejected," the organization can trace the sequence of tool calls the agent made: which data it read, which services it queried, what it wrote. This does not explain the model's reasoning, but it provides a complete audit trail of the actions that led to the decision.

For full GDPR Article 22 compliance, organizations need both the blackbox (what happened) and model-level explainability (why it happened). navra provides the former.

## What navra does not address

Compliance is broader than technology. navra provides technical controls, but several compliance requirements are organizational:

- **Data protection impact assessments** (GDPR Article 35) require human analysis of processing activities. navra provides the technical inventory (what data flows through which tools) but does not automate the assessment.
- **Training and awareness** (ISO 42001 Clause 7.2) requires that people understand the AI system. navra's documentation (including these learn chapters) contributes, but training programs are the organization's responsibility.
- **Vendor management** (SOC2 CC9.2) requires oversight of third-party providers. navra proxies upstream MCP servers, but the contractual and risk management of those providers is organizational.
- **Incident response** (SOC2 CC7.3) requires a process for responding to security events. navra's blackbox and metrics provide detection, but the response process -- who to notify, what to do, how to recover -- is defined by the organization.

## A practical compliance checklist

For organizations evaluating navra's compliance contributions, here is a checklist of what navra provides and what the organization must provide:

| Requirement | navra provides | Organization provides |
|---|---|---|
| Audit trail | Blackbox with hash chain | Log retention policy, archival |
| Human oversight | Pause button, approval policies | Operational procedures, training |
| Access control | Capability tokens, ACLs, Cedar | Token issuance process, role definitions |
| Data protection | PII detection, IFC labels | Data classification, DPIA |
| Incident detection | Metrics, blackbox queries | Alerting thresholds, response playbook |
| Tamper detection | Hash chain verification | Verification schedule, escalation process |
| Key management | HMAC signing, revocation lists | Key rotation, secure storage |

The pattern is consistent: navra provides technical mechanisms, and the organization provides the policies and processes that make those mechanisms effective. Neither is sufficient alone.

The honest position: navra provides technical building blocks for compliance. It does not provide compliance itself. The organization must configure the controls, write the policies, train the people, and hire the auditor.

## What's next

This is the final chapter of Part VI and the end of the Privacy section. You have seen how navra detects PII with regex patterns, named entity recognition, and ML classification. You have seen how the PrivacyRouter coordinates detectors efficiently. You have seen the false positive tradeoff and how operators tune the system. And you have seen how the technical controls map to regulatory requirements.

The learn track continues with Part VII, which covers deployment: how to install navra, configure it for your environment, and integrate it with your existing agent infrastructure.

Throughout Parts IV, V, and VI, we have moved from protocol mechanics (how messages flow) through verification (how we know the code is correct) to privacy and compliance (how we protect data and meet regulatory requirements). Each layer builds on the previous one: the protocol defines what navra speaks, verification proves the implementation is correct, and privacy controls protect the data that flows through the verified protocol.

The common thread is transparency. The protocol is open (JSON-RPC, MCP, A2A). The verification is documented (proof map, TLA+ specs). The privacy controls are configurable (PrivacyRouter, thresholds). And the compliance mapping is honest about what navra provides and what it does not. This transparency is not a weakness -- it is the foundation of trust in a security system.
