import { useCallback, useEffect, useRef, useState } from "react";

// --- AG-UI Event Types ---

export type AgUiEventType =
  | "RUN_STARTED"
  | "RUN_FINISHED"
  | "RUN_ERROR"
  | "TEXT_MESSAGE_START"
  | "TEXT_MESSAGE_CONTENT"
  | "TEXT_MESSAGE_END"
  | "TOOL_CALL_START"
  | "TOOL_CALL_ARGS"
  | "TOOL_CALL_END"
  | "REASONING_MESSAGE_START"
  | "REASONING_MESSAGE_CONTENT"
  | "REASONING_MESSAGE_END";

export interface AgUiEvent {
  type: AgUiEventType;
  timestamp: number;
  [key: string]: unknown;
}

// --- Navra NDJSON Event Types ---

interface NavraTextEvent {
  type: "text";
  content: string;
}

interface NavraToolCallEvent {
  type: "tool_call";
  tool: string;
  args: Record<string, unknown>;
  iteration?: number;
}

interface NavraToolResultEvent {
  type: "tool_result";
  tool: string;
  result: string;
  duration_ms?: number;
}

interface NavraThinkingEvent {
  type: "thinking";
  iteration: number;
  input_tokens?: number;
  output_tokens?: number;
  response_type?: string;
}

interface NavraDoneEvent {
  type: "done";
  session_id: string;
  iterations: number;
  usage?: { input_tokens: number; output_tokens: number };
}

interface NavraErrorEvent {
  type: "error";
  message: string;
}

type NavraEvent =
  | NavraTextEvent
  | NavraToolCallEvent
  | NavraToolResultEvent
  | NavraThinkingEvent
  | NavraDoneEvent
  | NavraErrorEvent;

// --- AG-UI State ---

export type AgentRunStatus = "idle" | "running" | "finished" | "error";

export interface ToolCallState {
  id: string;
  name: string;
  args: string;
  result?: string;
  durationMs?: number;
  status: "running" | "complete";
}

export interface AgentState {
  status: AgentRunStatus;
  messages: string;
  toolCalls: ToolCallState[];
  reasoning: string;
  error?: string;
  sessionId?: string;
  iterations: number;
  events: AgUiEvent[];
}

const initialState: AgentState = {
  status: "idle",
  messages: "",
  toolCalls: [],
  reasoning: "",
  iterations: 0,
  events: [],
};

// --- Adapter: Navra NDJSON → AG-UI Events ---

let toolCallCounter = 0;

export function mapNavraToAgUi(event: NavraEvent): AgUiEvent[] {
  const ts = Date.now();

  switch (event.type) {
    case "text":
      return [
        { type: "TEXT_MESSAGE_CONTENT", timestamp: ts, content: event.content },
      ];

    case "tool_call": {
      const id = `tc-${++toolCallCounter}`;
      return [
        {
          type: "TOOL_CALL_START",
          timestamp: ts,
          toolCallId: id,
          toolName: event.tool,
        },
        {
          type: "TOOL_CALL_ARGS",
          timestamp: ts,
          toolCallId: id,
          args: JSON.stringify(event.args),
        },
      ];
    }

    case "tool_result":
      return [
        {
          type: "TOOL_CALL_END",
          timestamp: ts,
          toolName: event.tool,
          result: event.result,
          durationMs: event.duration_ms,
        },
      ];

    case "thinking":
      return [
        {
          type: "REASONING_MESSAGE_CONTENT",
          timestamp: ts,
          iteration: event.iteration,
          inputTokens: event.input_tokens,
          outputTokens: event.output_tokens,
        },
      ];

    case "done":
      return [
        {
          type: "TEXT_MESSAGE_END",
          timestamp: ts,
        },
        {
          type: "RUN_FINISHED",
          timestamp: ts,
          sessionId: event.session_id,
          iterations: event.iterations,
          usage: event.usage,
        },
      ];

    case "error":
      return [
        {
          type: "RUN_ERROR",
          timestamp: ts,
          message: event.message,
        },
      ];

    default:
      return [];
  }
}

// --- Reducer ---

export function reduceAgentState(
  state: AgentState,
  event: AgUiEvent,
): AgentState {
  const events = [...state.events, event];

  switch (event.type) {
    case "RUN_STARTED":
      return { ...initialState, status: "running", events };

    case "TEXT_MESSAGE_CONTENT":
      return {
        ...state,
        messages: state.messages + (event.content as string),
        events,
      };

    case "TOOL_CALL_START":
      return {
        ...state,
        toolCalls: [
          ...state.toolCalls,
          {
            id: event.toolCallId as string,
            name: event.toolName as string,
            args: "",
            status: "running" as const,
          },
        ],
        events,
      };

    case "TOOL_CALL_ARGS": {
      const toolCalls = state.toolCalls.map((tc) =>
        tc.status === "running" && tc.args === ""
          ? { ...tc, args: event.args as string }
          : tc,
      );
      return { ...state, toolCalls, events };
    }

    case "TOOL_CALL_END": {
      const toolCalls = state.toolCalls.map((tc) =>
        tc.name === (event.toolName as string) && tc.status === "running"
          ? {
              ...tc,
              result: event.result as string,
              durationMs: event.durationMs as number | undefined,
              status: "complete" as const,
            }
          : tc,
      );
      return { ...state, toolCalls, events };
    }

    case "REASONING_MESSAGE_CONTENT":
      return {
        ...state,
        reasoning:
          state.reasoning +
          `[iteration ${event.iteration}] ` +
          `${event.inputTokens ?? 0}/${event.outputTokens ?? 0} tokens\n`,
        events,
      };

    case "RUN_FINISHED":
      return {
        ...state,
        status: "finished",
        sessionId: event.sessionId as string,
        iterations: (event.iterations as number) ?? state.iterations,
        events,
      };

    case "RUN_ERROR":
      return {
        ...state,
        status: "error",
        error: event.message as string,
        events,
      };

    default:
      return { ...state, events };
  }
}

// --- Hook ---

export interface UseNavraAgentOptions {
  baseUrl?: string;
  token?: string;
  maxEvents?: number;
}

export interface UseNavraAgentResult {
  state: AgentState;
  send: (prompt: string) => void;
  reset: () => void;
  isRunning: boolean;
}

export function useNavraAgent(
  options: UseNavraAgentOptions = {},
): UseNavraAgentResult {
  const { baseUrl = "", token, maxEvents = 200 } = options;
  const [state, setState] = useState<AgentState>(initialState);
  const abortRef = useRef<AbortController | null>(null);

  const send = useCallback(
    (prompt: string) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setState({
        ...initialState,
        status: "running",
        events: [{ type: "RUN_STARTED", timestamp: Date.now() }],
      });

      const headers: Record<string, string> = {
        "content-type": "application/json",
      };
      if (token) {
        headers["authorization"] = `Bearer ${token}`;
      }

      (async () => {
        try {
          const response = await fetch(`${baseUrl}/api/chat/agent`, {
            method: "POST",
            headers,
            body: JSON.stringify({ prompt }),
            signal: controller.signal,
          });

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }

          if (!response.body) {
            throw new Error("No response body");
          }

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
              if (!line.trim()) continue;
              try {
                const navraEvent = JSON.parse(line) as NavraEvent;
                const agUiEvents = mapNavraToAgUi(navraEvent);
                setState((prev) => {
                  let next = prev;
                  for (const e of agUiEvents) {
                    next = reduceAgentState(next, e);
                  }
                  if (next.events.length > maxEvents) {
                    next = {
                      ...next,
                      events: next.events.slice(-maxEvents),
                    };
                  }
                  return next;
                });
              } catch {
                // skip malformed JSON lines
              }
            }
          }
        } catch (err) {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setState((prev) =>
            reduceAgentState(prev, {
              type: "RUN_ERROR",
              timestamp: Date.now(),
              message: err instanceof Error ? err.message : String(err),
            }),
          );
        }
      })();
    },
    [baseUrl, token, maxEvents],
  );

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState(initialState);
  }, []);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  return {
    state,
    send,
    reset,
    isRunning: state.status === "running",
  };
}
