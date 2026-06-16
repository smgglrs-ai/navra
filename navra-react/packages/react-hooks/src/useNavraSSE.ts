import { useEffect, useRef, useState } from "react";

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}

export interface UseNavraSSEOptions {
  url?: string;
  sessionId?: string;
  enabled?: boolean;
  onEvent?: (event: JsonRpcNotification) => void;
}

export type SSEStatus = "connecting" | "connected" | "disconnected" | "error";

export interface UseNavraSSEResult {
  status: SSEStatus;
  lastEvent: JsonRpcNotification | null;
  error: Error | null;
}

export function useNavraSSE(
  options: UseNavraSSEOptions = {},
): UseNavraSSEResult {
  const {
    url = "/mcp",
    sessionId,
    enabled = true,
    onEvent,
  } = options;

  const [status, setStatus] = useState<SSEStatus>("disconnected");
  const [lastEvent, setLastEvent] = useState<JsonRpcNotification | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    if (!enabled || !sessionId) return;

    const headers: Record<string, string> = {
      "mcp-session-id": sessionId,
    };

    setStatus("connecting");
    setError(null);

    const abortController = new AbortController();

    (async () => {
      try {
        const response = await fetch(url, {
          headers,
          signal: abortController.signal,
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        if (!response.body) {
          throw new Error("No response body for SSE stream");
        }

        setStatus("connected");
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              const data = line.slice(6);
              try {
                const notification = JSON.parse(data) as JsonRpcNotification;
                setLastEvent(notification);
                onEventRef.current?.(notification);
              } catch {
                // skip malformed JSON
              }
            }
          }
        }

        setStatus("disconnected");
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(err instanceof Error ? err : new Error(String(err)));
        setStatus("error");
      }
    })();

    return () => {
      abortController.abort();
      setStatus("disconnected");
    };
  }, [url, sessionId, enabled]);

  return { status, lastEvent, error };
}
