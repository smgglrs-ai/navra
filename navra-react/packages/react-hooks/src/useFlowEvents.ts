import { useCallback, useState } from "react";
import { type JsonRpcNotification, useNavraSSE } from "./useNavraSSE";

export type FlowTaskStatus =
  | "pending"
  | "ready"
  | "running"
  | "complete"
  | "failed"
  | "skipped";

export interface FlowTask {
  id: string;
  specialist: string;
  mandate: string;
  status: FlowTaskStatus;
  dependsOn: string[];
  validationScore?: number;
  output?: string;
  tokenUsage?: { prompt: number; completion: number };
}

export interface FlowBackEdge {
  from: string;
  to: string;
  iteration: number;
}

export interface FlowState {
  tasks: Map<string, FlowTask>;
  backEdges: FlowBackEdge[];
  completed: boolean;
  totalTokens?: { prompt: number; completion: number };
}

export interface FlowDefinition {
  tasks: Array<{
    id: string;
    specialist: string;
    mandate: string;
    dependsOn: string[];
  }>;
}

export interface UseFlowEventsOptions {
  baseUrl?: string;
  sessionId?: string;
  enabled?: boolean;
  initialDefinition?: FlowDefinition;
}

export interface UseFlowEventsResult {
  state: FlowState;
  reset: (definition?: FlowDefinition) => void;
}

function buildInitialState(def?: FlowDefinition): FlowState {
  const tasks = new Map<string, FlowTask>();
  if (def) {
    for (const t of def.tasks) {
      tasks.set(t.id, {
        id: t.id,
        specialist: t.specialist,
        mandate: t.mandate,
        status: "pending",
        dependsOn: t.dependsOn,
      });
    }
  }
  return { tasks, backEdges: [], completed: false };
}

export function useFlowEvents(
  options: UseFlowEventsOptions = {},
): UseFlowEventsResult {
  const { baseUrl = "", sessionId, enabled = true, initialDefinition } = options;
  const [state, setState] = useState<FlowState>(() =>
    buildInitialState(initialDefinition),
  );

  const handleEvent = useCallback((notification: JsonRpcNotification) => {
    const params = notification.params as Record<string, unknown>;

    setState((prev) => {
      const tasks = new Map(prev.tasks);
      const backEdges = [...prev.backEdges];

      switch (notification.method) {
        case "notifications/flow/node_started": {
          const id = params.task_id as string;
          const existing = tasks.get(id);
          if (existing) {
            tasks.set(id, { ...existing, status: "running" });
          } else {
            tasks.set(id, {
              id,
              specialist: (params.specialist as string) ?? id,
              mandate: "",
              status: "running",
              dependsOn: [],
            });
          }
          break;
        }
        case "notifications/flow/node_completed": {
          const id = params.task_id as string;
          const existing = tasks.get(id);
          if (existing) {
            tasks.set(id, {
              ...existing,
              status: "complete",
              output: params.output_preview as string | undefined,
              tokenUsage: {
                prompt: (params.prompt_tokens as number) ?? 0,
                completion: (params.completion_tokens as number) ?? 0,
              },
            });
          }
          break;
        }
        case "notifications/flow/node_failed": {
          const id = params.task_id as string;
          const existing = tasks.get(id);
          if (existing) {
            tasks.set(id, {
              ...existing,
              status: "failed",
              output: params.error as string | undefined,
            });
          }
          break;
        }
        case "notifications/flow/node_skipped": {
          const id = params.task_id as string;
          const existing = tasks.get(id);
          if (existing) {
            tasks.set(id, { ...existing, status: "skipped" });
          }
          break;
        }
        case "notifications/flow/back_edge": {
          backEdges.push({
            from: params.from as string,
            to: params.to as string,
            iteration: (params.iteration as number) ?? 1,
          });
          break;
        }
        case "notifications/flow/completed": {
          return {
            tasks,
            backEdges,
            completed: true,
            totalTokens: {
              prompt: (params.total_prompt_tokens as number) ?? 0,
              completion: (params.total_completion_tokens as number) ?? 0,
            },
          };
        }
        default:
          return prev;
      }

      return { ...prev, tasks, backEdges };
    });
  }, []);

  useNavraSSE({
    url: `${baseUrl}/mcp`,
    sessionId,
    enabled: enabled && !!sessionId,
    onEvent: handleEvent,
  });

  const reset = useCallback(
    (definition?: FlowDefinition) => {
      setState(buildInitialState(definition ?? initialDefinition));
    },
    [initialDefinition],
  );

  return { state, reset };
}
