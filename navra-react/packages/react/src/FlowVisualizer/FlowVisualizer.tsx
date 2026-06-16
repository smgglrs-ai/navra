import React, { useMemo } from "react";
import {
  ReactFlow,
  type Node,
  type Edge,
  Background,
  Controls,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { EmptyState, EmptyStateBody } from "@patternfly/react-core";
import {
  useFlowEvents,
  type FlowDefinition,
  type FlowState,
} from "@navra/react-hooks";
import { TaskNode, type TaskNodeData } from "./TaskNode";

export interface FlowVisualizerProps {
  definition?: FlowDefinition;
  state?: FlowState;
  baseUrl?: string;
  sessionId?: string;
  height?: number | string;
}

const nodeTypes = { task: TaskNode };

function layoutNodes(state: FlowState): { nodes: Node[]; edges: Edge[] } {
  const tasks = Array.from(state.tasks.values());
  if (tasks.length === 0) return { nodes: [], edges: [] };

  const levels = new Map<string, number>();
  const visited = new Set<string>();

  function assignLevel(id: string): number {
    if (levels.has(id)) return levels.get(id)!;
    if (visited.has(id)) return 0;
    visited.add(id);

    const task = state.tasks.get(id);
    if (!task || task.dependsOn.length === 0) {
      levels.set(id, 0);
      return 0;
    }

    const maxParent = Math.max(
      ...task.dependsOn.map((dep) => assignLevel(dep)),
    );
    const level = maxParent + 1;
    levels.set(id, level);
    return level;
  }

  for (const task of tasks) {
    assignLevel(task.id);
  }

  const byLevel = new Map<number, string[]>();
  for (const [id, level] of levels) {
    const list = byLevel.get(level) ?? [];
    list.push(id);
    byLevel.set(level, list);
  }

  const nodes: Node[] = [];
  for (const [level, ids] of byLevel) {
    ids.forEach((id, i) => {
      const task = state.tasks.get(id)!;
      nodes.push({
        id,
        type: "task",
        position: {
          x: i * 250 - ((ids.length - 1) * 250) / 2,
          y: level * 150,
        },
        data: {
          specialist: task.specialist,
          mandate: task.mandate,
          status: task.status,
          validationScore: task.validationScore,
          tokenUsage: task.tokenUsage,
        } satisfies TaskNodeData,
      });
    });
  }

  const edges: Edge[] = [];
  for (const task of tasks) {
    for (const dep of task.dependsOn) {
      edges.push({
        id: `${dep}->${task.id}`,
        source: dep,
        target: task.id,
        animated: task.status === "running",
        style: { stroke: "#6a6e73" },
      });
    }
  }

  for (const be of state.backEdges) {
    edges.push({
      id: `back-${be.from}->${be.to}-${be.iteration}`,
      source: be.from,
      target: be.to,
      animated: true,
      style: { stroke: "#f0ab00", strokeDasharray: "5 5" },
      label: `retry ${be.iteration}`,
    });
  }

  return { nodes, edges };
}

export function FlowVisualizer({
  definition,
  state: externalState,
  baseUrl,
  sessionId,
  height = 500,
}: FlowVisualizerProps) {
  const { state: sseState } = useFlowEvents({
    baseUrl,
    sessionId,
    enabled: !!sessionId && !externalState,
    initialDefinition: definition,
  });

  const state = externalState ?? sseState;

  const { nodes, edges } = useMemo(() => layoutNodes(state), [state]);

  if (state.tasks.size === 0) {
    return (
      <EmptyState titleText="No Flow" headingLevel="h4">
        <EmptyStateBody>
          No flow definition loaded. Provide a definition or connect to a
          running navra flow via SSE.
        </EmptyStateBody>
      </EmptyState>
    );
  }

  return (
    <div style={{ height, width: "100%" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
        <Controls />
      </ReactFlow>
    </div>
  );
}
