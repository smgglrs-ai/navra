import { useCallback, useState } from "react";
import { type JsonRpcNotification, useNavraSSE } from "./useNavraSSE";

export type ToolOutcome = "success" | "denied" | "error" | "pending";

export interface ToolEvent {
  id: string;
  toolName: string;
  agentName: string;
  outcome: ToolOutcome;
  durationMs?: number;
  ifcLabel?: string;
  timestamp: number;
}

export interface UseToolEventsOptions {
  baseUrl?: string;
  sessionId?: string;
  enabled?: boolean;
  maxEvents?: number;
}

export interface UseToolEventsResult {
  events: ToolEvent[];
  clear: () => void;
}

interface ToolCallNotificationParams {
  request_id: string;
  tool_name: string;
  agent_name: string;
  outcome: ToolOutcome;
  duration_ms?: number;
  ifc_label?: string;
}

let eventCounter = 0;

export function useToolEvents(
  options: UseToolEventsOptions = {},
): UseToolEventsResult {
  const { baseUrl = "", sessionId, enabled = true, maxEvents = 500 } = options;
  const [events, setEvents] = useState<ToolEvent[]>([]);

  const handleEvent = useCallback(
    (notification: JsonRpcNotification) => {
      if (notification.method !== "notifications/tool/completed") return;
      const params = notification.params as ToolCallNotificationParams;
      const event: ToolEvent = {
        id: `te-${++eventCounter}`,
        toolName: params.tool_name,
        agentName: params.agent_name,
        outcome: params.outcome,
        durationMs: params.duration_ms,
        ifcLabel: params.ifc_label,
        timestamp: Date.now(),
      };
      setEvents((prev) => {
        const next = [event, ...prev];
        return next.length > maxEvents ? next.slice(0, maxEvents) : next;
      });
    },
    [maxEvents],
  );

  useNavraSSE({
    url: `${baseUrl}/mcp`,
    sessionId,
    enabled,
    onEvent: handleEvent,
  });

  const clear = useCallback(() => setEvents([]), []);

  return { events, clear };
}
