import { useMemo } from "react";
import type { FlowKind } from "./useYamlSync";

export type ValidationSeverity = "error" | "warning";

export interface ValidationError {
  id: string;
  severity: ValidationSeverity;
  message: string;
  nodeIds?: string[];
}

export interface UseFlowValidationOptions {
  nodes: Array<{ id: string; data: Record<string, unknown> }>;
  edges: Array<{ source: string; target: string }>;
  kind: FlowKind;
  entry?: string;
}

export interface UseFlowValidationResult {
  errors: ValidationError[];
  isValid: boolean;
}

/**
 * Pure validation function for flow graphs.
 */
export function validateFlow(
  nodes: Array<{ id: string; data: Record<string, unknown> }>,
  edges: Array<{ source: string; target: string }>,
  kind: FlowKind,
  entry?: string,
): ValidationError[] {
  const errors: ValidationError[] = [];
  const nodeIds = new Set(nodes.map((n) => n.id));

  // Empty graph
  if (nodes.length === 0) {
    errors.push({
      id: "empty-graph",
      severity: "warning",
      message: "Flow has no nodes",
    });
    return errors;
  }

  // Duplicate node IDs
  const idCounts = new Map<string, number>();
  for (const node of nodes) {
    idCounts.set(node.id, (idCounts.get(node.id) ?? 0) + 1);
  }
  for (const [id, count] of idCounts) {
    if (count > 1) {
      errors.push({
        id: `duplicate-${id}`,
        severity: "error",
        message: `Duplicate node ID: "${id}" (appears ${count} times)`,
        nodeIds: [id],
      });
    }
  }

  // Dangling edges
  for (const edge of edges) {
    if (!nodeIds.has(edge.source)) {
      errors.push({
        id: `dangling-source-${edge.source}-${edge.target}`,
        severity: "error",
        message: `Edge source "${edge.source}" does not exist`,
      });
    }
    if (!nodeIds.has(edge.target)) {
      errors.push({
        id: `dangling-target-${edge.source}-${edge.target}`,
        severity: "error",
        message: `Edge target "${edge.target}" does not exist`,
      });
    }
  }

  if (kind === "dag") {
    validateDag(nodes, edges, nodeIds, errors);
  } else {
    validateHandoff(nodes, edges, nodeIds, entry, errors);
  }

  return errors;
}

function validateDag(
  nodes: Array<{ id: string; data: Record<string, unknown> }>,
  edges: Array<{ source: string; target: string }>,
  nodeIds: Set<string>,
  errors: ValidationError[],
): void {
  // Required fields for DAG nodes
  for (const node of nodes) {
    if (!node.data.specialist) {
      errors.push({
        id: `missing-specialist-${node.id}`,
        severity: "error",
        message: `Node "${node.id}" is missing required field: specialist`,
        nodeIds: [node.id],
      });
    }
    if (!node.data.mandate) {
      errors.push({
        id: `missing-mandate-${node.id}`,
        severity: "error",
        message: `Node "${node.id}" is missing required field: mandate`,
        nodeIds: [node.id],
      });
    }
  }

  // Cycle detection (DFS-based)
  const adj = new Map<string, string[]>();
  for (const id of nodeIds) {
    adj.set(id, []);
  }
  for (const edge of edges) {
    if (nodeIds.has(edge.source) && nodeIds.has(edge.target)) {
      adj.get(edge.source)!.push(edge.target);
    }
  }

  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>();
  for (const id of nodeIds) color.set(id, WHITE);

  const cycleNodes: string[] = [];

  function dfs(u: string): boolean {
    color.set(u, GRAY);
    for (const v of adj.get(u) ?? []) {
      if (color.get(v) === GRAY) {
        cycleNodes.push(u, v);
        return true;
      }
      if (color.get(v) === WHITE && dfs(v)) {
        return true;
      }
    }
    color.set(u, BLACK);
    return false;
  }

  for (const id of nodeIds) {
    if (color.get(id) === WHITE && dfs(id)) {
      break;
    }
  }

  if (cycleNodes.length > 0) {
    errors.push({
      id: "cycle-detected",
      severity: "error",
      message: "DAG contains a cycle",
      nodeIds: [...new Set(cycleNodes)],
    });
  }

  // Unreachable nodes (no incoming edges and has dependencies it should receive from)
  const hasIncoming = new Set<string>();
  for (const edge of edges) {
    if (nodeIds.has(edge.target)) {
      hasIncoming.add(edge.target);
    }
  }
  // Root nodes (no incoming) are fine. But if there are edges from a node
  // that nothing points to and it's not the only root, warn.
  const roots = [...nodeIds].filter((id) => !hasIncoming.has(id));
  if (roots.length > 1) {
    // Multiple roots are fine in a DAG — they just run in parallel.
    // We only warn about truly unreachable nodes: nodes that no edge
    // points to AND that have no outgoing edges either (isolated).
    const hasOutgoing = new Set<string>();
    for (const edge of edges) {
      if (nodeIds.has(edge.source)) {
        hasOutgoing.add(edge.source);
      }
    }
    for (const id of nodeIds) {
      if (!hasIncoming.has(id) && !hasOutgoing.has(id) && nodeIds.size > 1) {
        errors.push({
          id: `unreachable-${id}`,
          severity: "warning",
          message: `Node "${id}" is isolated (no connections)`,
          nodeIds: [id],
        });
      }
    }
  }
}

function validateHandoff(
  nodes: Array<{ id: string; data: Record<string, unknown> }>,
  _edges: Array<{ source: string; target: string }>,
  nodeIds: Set<string>,
  entry: string | undefined,
  errors: ValidationError[],
): void {
  // Entry node must exist
  if (!entry) {
    errors.push({
      id: "missing-entry",
      severity: "error",
      message: "Handoff flow has no entry node specified",
    });
  } else if (!nodeIds.has(entry)) {
    errors.push({
      id: "invalid-entry",
      severity: "error",
      message: `Entry node "${entry}" does not exist in the flow`,
    });
  }

  // Required fields for handoff nodes
  for (const node of nodes) {
    if (!node.data.endpoint) {
      errors.push({
        id: `missing-endpoint-${node.id}`,
        severity: "error",
        message: `Node "${node.id}" is missing required field: endpoint`,
        nodeIds: [node.id],
      });
    }
    if (!node.data.modelUrl) {
      errors.push({
        id: `missing-modelUrl-${node.id}`,
        severity: "error",
        message: `Node "${node.id}" is missing required field: modelUrl`,
        nodeIds: [node.id],
      });
    }
    if (!node.data.modelName) {
      errors.push({
        id: `missing-modelName-${node.id}`,
        severity: "error",
        message: `Node "${node.id}" is missing required field: modelName`,
        nodeIds: [node.id],
      });
    }
  }
}

/**
 * React hook for live flow validation.
 */
export function useFlowValidation(
  options: UseFlowValidationOptions,
): UseFlowValidationResult {
  const { nodes, edges, kind, entry } = options;

  const errors = useMemo(
    () => validateFlow(nodes, edges, kind, entry),
    [nodes, edges, kind, entry],
  );

  return {
    errors,
    isValid: errors.filter((e) => e.severity === "error").length === 0,
  };
}
