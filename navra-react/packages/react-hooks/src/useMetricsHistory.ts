import { useEffect, useRef, useState } from "react";
import { useNavraMetrics, type NavraMetrics } from "./useNavraMetrics";

export interface MetricsSnapshot {
  timestamp: number;
  metrics: NavraMetrics;
}

export interface UseMetricsHistoryOptions {
  url?: string;
  intervalMs?: number;
  maxSnapshots?: number;
  enabled?: boolean;
}

export interface UseMetricsHistoryResult {
  current: NavraMetrics;
  history: MetricsSnapshot[];
  error: Error | null;
  loading: boolean;
}

export function useMetricsHistory(
  options: UseMetricsHistoryOptions = {},
): UseMetricsHistoryResult {
  const { maxSnapshots = 60, ...metricsOptions } = options;
  const { metrics, error, loading } = useNavraMetrics(metricsOptions);
  const [history, setHistory] = useState<MetricsSnapshot[]>([]);
  const prevRef = useRef<string>("");

  useEffect(() => {
    const serialized = JSON.stringify(metrics);
    if (serialized === prevRef.current) return;
    prevRef.current = serialized;

    setHistory((prev) => {
      const next = [...prev, { timestamp: Date.now(), metrics }];
      return next.length > maxSnapshots ? next.slice(-maxSnapshots) : next;
    });
  }, [metrics, maxSnapshots]);

  return { current: metrics, history, error, loading };
}
