import { useCallback, useEffect, useRef, useState } from "react";

export interface NavraMetrics {
  toolCalls: number;
  toolErrors: number;
  toolDenied: number;
  toolApproved: number;
  safetyTriggers: number;
  safetyBlocked: number;
  safetyRedacted: number;
  ifcTaintElevations: number;
  ifcWriteDenials: number;
  ifcReadDenials: number;
  sessionsCreated: number;
  sessionsActive: number;
  authFailures: number;
  budgetTruncations: number;
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  effectiveTokens: number;
  modelRefusals: number;
  modelFallbackAttempts: number;
  modelFallbackSuccesses: number;
  toolScanTotal: number;
  toolScanBlocked: number;
  toolScanSuspicious: number;
  integrityAlerts: number;
  integrityMalicious: number;
  leakageSimilarityBlocks: number;
  leakageSemanticBlocks: number;
}

const METRIC_MAP: Record<string, keyof NavraMetrics> = {
  tool_calls_total: "toolCalls",
  tool_calls_errors_total: "toolErrors",
  tool_calls_denied_total: "toolDenied",
  tool_calls_approved_total: "toolApproved",
  safety_triggers_total: "safetyTriggers",
  safety_triggers_blocked_total: "safetyBlocked",
  safety_triggers_redacted_total: "safetyRedacted",
  ifc_taint_elevations_total: "ifcTaintElevations",
  ifc_write_denials_total: "ifcWriteDenials",
  ifc_read_denials_total: "ifcReadDenials",
  sessions_created_total: "sessionsCreated",
  sessions_active: "sessionsActive",
  auth_failures_total: "authFailures",
  budget_truncations_total: "budgetTruncations",
  input_tokens_total: "inputTokens",
  output_tokens_total: "outputTokens",
  cached_tokens_total: "cachedTokens",
  effective_tokens_total: "effectiveTokens",
  model_refusals_total: "modelRefusals",
  model_fallback_attempts_total: "modelFallbackAttempts",
  model_fallback_successes_total: "modelFallbackSuccesses",
  tool_scan_total: "toolScanTotal",
  tool_scan_blocked_total: "toolScanBlocked",
  tool_scan_suspicious_total: "toolScanSuspicious",
  integrity_alerts_total: "integrityAlerts",
  integrity_alerts_malicious_total: "integrityMalicious",
  leakage_similarity_blocks_total: "leakageSimilarityBlocks",
  leakage_semantic_blocks_total: "leakageSemanticBlocks",
};

const INITIAL_METRICS: NavraMetrics = Object.fromEntries(
  Object.values(METRIC_MAP).map((key) => [key, 0]),
) as unknown as NavraMetrics;

export function parsePrometheusText(text: string): NavraMetrics {
  const metrics = { ...INITIAL_METRICS };
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || line.trim() === "") continue;
    const spaceIdx = line.indexOf(" ");
    if (spaceIdx === -1) continue;
    const name = line.slice(0, spaceIdx);
    const value = Number(line.slice(spaceIdx + 1));
    const key = METRIC_MAP[name];
    if (key !== undefined && !Number.isNaN(value)) {
      metrics[key] = value;
    }
  }
  return metrics;
}

export interface UseNavraMetricsOptions {
  url?: string;
  intervalMs?: number;
  enabled?: boolean;
}

export interface UseNavraMetricsResult {
  metrics: NavraMetrics;
  error: Error | null;
  loading: boolean;
  refresh: () => void;
}

export function useNavraMetrics(
  options: UseNavraMetricsOptions = {},
): UseNavraMetricsResult {
  const {
    url = "/metrics",
    intervalMs = 5000,
    enabled = true,
  } = options;

  const [metrics, setMetrics] = useState<NavraMetrics>(INITIAL_METRICS);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  const fetchMetrics = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      setMetrics(parsePrometheusText(text));
      setError(null);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [url]);

  useEffect(() => {
    if (!enabled) return;
    fetchMetrics();
    const id = setInterval(fetchMetrics, intervalMs);
    return () => {
      clearInterval(id);
      abortRef.current?.abort();
    };
  }, [enabled, intervalMs, fetchMetrics]);

  return { metrics, error, loading, refresh: fetchMetrics };
}
