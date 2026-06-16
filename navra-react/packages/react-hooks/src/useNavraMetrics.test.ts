import { describe, expect, it } from "vitest";
import { parsePrometheusText } from "./useNavraMetrics";

const SAMPLE_METRICS = `# HELP tool_calls_total Total tool calls
# TYPE tool_calls_total counter
tool_calls_total 42
tool_calls_errors_total 3
tool_calls_denied_total 7
safety_triggers_total 12
safety_triggers_blocked_total 5
safety_triggers_redacted_total 2
ifc_taint_elevations_total 1
sessions_created_total 10
sessions_active 4
auth_failures_total 0
budget_truncations_total 8
input_tokens_total 15000
output_tokens_total 3000
cached_tokens_total 500
effective_tokens_total 27050
model_refusals_total 2
tool_scan_total 100
tool_scan_blocked_total 3
tool_scan_suspicious_total 5
integrity_alerts_total 1
integrity_alerts_malicious_total 0
leakage_similarity_blocks_total 2
leakage_semantic_blocks_total 1
`;

describe("parsePrometheusText", () => {
  it("parses all known metrics", () => {
    const metrics = parsePrometheusText(SAMPLE_METRICS);
    expect(metrics.toolCalls).toBe(42);
    expect(metrics.toolErrors).toBe(3);
    expect(metrics.toolDenied).toBe(7);
    expect(metrics.safetyTriggers).toBe(12);
    expect(metrics.safetyBlocked).toBe(5);
    expect(metrics.sessionsActive).toBe(4);
    expect(metrics.inputTokens).toBe(15000);
    expect(metrics.effectiveTokens).toBe(27050);
    expect(metrics.modelRefusals).toBe(2);
    expect(metrics.toolScanBlocked).toBe(3);
    expect(metrics.integrityAlerts).toBe(1);
    expect(metrics.leakageSimilarityBlocks).toBe(2);
  });

  it("ignores comment lines and empty lines", () => {
    const text = `# HELP foo
# TYPE foo counter

tool_calls_total 10
`;
    const metrics = parsePrometheusText(text);
    expect(metrics.toolCalls).toBe(10);
  });

  it("returns zeros for missing metrics", () => {
    const metrics = parsePrometheusText("");
    expect(metrics.toolCalls).toBe(0);
    expect(metrics.sessionsActive).toBe(0);
  });

  it("ignores unknown metric names", () => {
    const text = "unknown_metric 999\ntool_calls_total 5\n";
    const metrics = parsePrometheusText(text);
    expect(metrics.toolCalls).toBe(5);
  });
});
