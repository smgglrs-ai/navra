import { useCallback, useMemo, useState } from "react";
import { type JsonRpcNotification, useNavraSSE } from "./useNavraSSE";

export type ApprovalStatus = "pending" | "approved" | "denied" | "timed_out";

export interface PendingApproval {
  requestId: string;
  toolName: string;
  argumentsSummary: string;
  agentName: string;
  status: ApprovalStatus;
  createdAt: number;
}

export interface UseApprovalQueueOptions {
  baseUrl?: string;
  sessionId?: string;
  enabled?: boolean;
}

export interface UseApprovalQueueResult {
  pending: PendingApproval[];
  approve: (requestId: string) => Promise<void>;
  deny: (requestId: string, reason?: string) => Promise<void>;
  error: Error | null;
}

interface ApprovalNotificationParams {
  request_id: string;
  tool_name: string;
  arguments_summary: string;
  agent_name: string;
}

interface ApprovalResolvedParams {
  request_id: string;
  status: ApprovalStatus;
}

export function useApprovalQueue(
  options: UseApprovalQueueOptions = {},
): UseApprovalQueueResult {
  const { baseUrl = "", sessionId, enabled = true } = options;
  const [approvals, setApprovals] = useState<Map<string, PendingApproval>>(
    new Map(),
  );
  const [error, setError] = useState<Error | null>(null);

  const handleEvent = useCallback((event: JsonRpcNotification) => {
    if (event.method === "notifications/approval/pending") {
      const params = event.params as ApprovalNotificationParams;
      setApprovals((prev) => {
        const next = new Map(prev);
        next.set(params.request_id, {
          requestId: params.request_id,
          toolName: params.tool_name,
          argumentsSummary: params.arguments_summary,
          agentName: params.agent_name,
          status: "pending",
          createdAt: Date.now(),
        });
        return next;
      });
    } else if (event.method === "notifications/approval/resolved") {
      const params = event.params as ApprovalResolvedParams;
      setApprovals((prev) => {
        const next = new Map(prev);
        const existing = next.get(params.request_id);
        if (existing) {
          next.set(params.request_id, { ...existing, status: params.status });
        }
        return next;
      });
    }
  }, []);

  useNavraSSE({
    url: `${baseUrl}/mcp`,
    sessionId,
    enabled,
    onEvent: handleEvent,
  });

  const approve = useCallback(
    async (requestId: string) => {
      try {
        const res = await fetch(`${baseUrl}/approvals/${requestId}/approve`, {
          method: "POST",
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        setApprovals((prev) => {
          const next = new Map(prev);
          const existing = next.get(requestId);
          if (existing) {
            next.set(requestId, { ...existing, status: "approved" });
          }
          return next;
        });
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
      }
    },
    [baseUrl],
  );

  const deny = useCallback(
    async (requestId: string, reason?: string) => {
      try {
        const res = await fetch(`${baseUrl}/approvals/${requestId}/deny`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason: reason ?? "Denied by operator" }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        setApprovals((prev) => {
          const next = new Map(prev);
          const existing = next.get(requestId);
          if (existing) {
            next.set(requestId, { ...existing, status: "denied" });
          }
          return next;
        });
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
      }
    },
    [baseUrl],
  );

  const pending = useMemo(
    () =>
      Array.from(approvals.values()).filter((a) => a.status === "pending"),
    [approvals],
  );

  return { pending, approve, deny, error };
}
