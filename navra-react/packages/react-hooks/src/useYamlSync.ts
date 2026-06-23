import * as yaml from "js-yaml";

export type FlowKind = "dag" | "handoff";

export interface FlowMeta {
  kind: FlowKind;
  name: string;
  description?: string;
  entry?: string;
  maxHops?: number;
}

export interface DagNodeData {
  specialist: string;
  mandate: string;
  expectedOutput?: string;
  parameters?: Record<string, string>;
  [key: string]: unknown;
}

export interface HandoffNodeData {
  endpoint: string;
  modelUrl: string;
  modelName: string;
  systemPrompt: string;
  apiKey?: string;
  maxIterations?: number;
  temperature?: number;
  maxTokens?: number;
  clearance?: string;
  [key: string]: unknown;
}

export interface EditorEdgeData {
  description?: string;
  [key: string]: unknown;
}

interface GraphNode {
  id: string;
  position: { x: number; y: number };
  data: Record<string, unknown>;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  data?: Record<string, unknown>;
}

export interface GraphState {
  nodes: GraphNode[];
  edges: GraphEdge[];
  flowMeta: FlowMeta;
}

// --- YAML structure types for serialization ---

interface YamlDagTask {
  id: string;
  specialist: string;
  mandate: string;
  depends_on?: string[];
  expected_output?: string;
}

interface YamlDagFlow {
  kind: "dag";
  name: string;
  description?: string;
  tasks: YamlDagTask[];
}

interface YamlHandoffNode {
  id: string;
  endpoint: string;
  model_url: string;
  model_name: string;
  system_prompt?: string;
  api_key?: string;
  max_iterations?: number;
  temperature?: number;
  max_tokens?: number;
  clearance?: string;
}

interface YamlHandoffEdge {
  from: string;
  to: string;
  description: string;
}

interface YamlHandoffFlow {
  kind: "handoff";
  name: string;
  description?: string;
  entry: string;
  max_hops?: number;
  nodes: YamlHandoffNode[];
  edges: YamlHandoffEdge[];
}

/**
 * Convert React Flow graph state to navra YAML string.
 */
export function graphToYaml(
  nodes: GraphNode[],
  edges: GraphEdge[],
  flowMeta: FlowMeta,
): string {
  if (flowMeta.kind === "dag") {
    return dagToYaml(nodes, edges, flowMeta);
  }
  return handoffToYaml(nodes, edges, flowMeta);
}

function dagToYaml(
  nodes: GraphNode[],
  edges: GraphEdge[],
  flowMeta: FlowMeta,
): string {
  // Build depends_on map from edges (source is dependency, target is dependent)
  const depsMap = new Map<string, string[]>();
  for (const edge of edges) {
    const deps = depsMap.get(edge.target) ?? [];
    deps.push(edge.source);
    depsMap.set(edge.target, deps);
  }

  const tasks: YamlDagTask[] = nodes.map((node) => {
    const data = node.data as DagNodeData;
    const task: YamlDagTask = {
      id: node.id,
      specialist: data.specialist || "",
      mandate: data.mandate || "",
    };
    const deps = depsMap.get(node.id);
    if (deps && deps.length > 0) {
      task.depends_on = deps;
    }
    if (data.expectedOutput) {
      task.expected_output = data.expectedOutput;
    }
    return task;
  });

  const flow: YamlDagFlow = {
    kind: "dag",
    name: flowMeta.name,
    tasks,
  };
  if (flowMeta.description) {
    flow.description = flowMeta.description;
  }

  return yaml.dump(flow, { lineWidth: -1, noRefs: true });
}

function handoffToYaml(
  nodes: GraphNode[],
  edges: GraphEdge[],
  flowMeta: FlowMeta,
): string {
  const yamlNodes: YamlHandoffNode[] = nodes.map((node) => {
    const data = node.data as HandoffNodeData;
    const n: YamlHandoffNode = {
      id: node.id,
      endpoint: data.endpoint || "",
      model_url: data.modelUrl || "",
      model_name: data.modelName || "",
    };
    if (data.systemPrompt) n.system_prompt = data.systemPrompt;
    if (data.apiKey) n.api_key = data.apiKey;
    if (data.maxIterations !== undefined) n.max_iterations = data.maxIterations;
    if (data.temperature !== undefined) n.temperature = data.temperature;
    if (data.maxTokens !== undefined) n.max_tokens = data.maxTokens;
    if (data.clearance) n.clearance = data.clearance;
    return n;
  });

  const yamlEdges: YamlHandoffEdge[] = edges.map((edge) => ({
    from: edge.source,
    to: edge.target,
    description: (edge.data as EditorEdgeData)?.description || "",
  }));

  const flow: YamlHandoffFlow = {
    kind: "handoff",
    name: flowMeta.name,
    entry: flowMeta.entry || (nodes.length > 0 ? nodes[0].id : ""),
    nodes: yamlNodes,
    edges: yamlEdges,
  };
  if (flowMeta.description) flow.description = flowMeta.description;
  if (flowMeta.maxHops !== undefined) flow.max_hops = flowMeta.maxHops;

  return yaml.dump(flow, { lineWidth: -1, noRefs: true });
}

/**
 * Parse a navra YAML flow string into React Flow graph state.
 */
export function yamlToGraph(yamlStr: string): GraphState {
  try {
    const doc = yaml.load(yamlStr) as Record<string, unknown>;
    if (!doc || typeof doc !== "object") {
      return {
        nodes: [],
        edges: [],
        flowMeta: { kind: "dag", name: "" },
      };
    }

    const kind = (doc.kind as string) === "handoff" ? "handoff" : "dag";

    if (kind === "dag") {
      return parseDagYaml(doc);
    }
    return parseHandoffYaml(doc);
  } catch {
    return {
      nodes: [],
      edges: [],
      flowMeta: { kind: "dag", name: "" },
    };
  }
}

function parseDagYaml(doc: Record<string, unknown>): GraphState {
  const tasks = (doc.tasks as YamlDagTask[]) ?? [];

  // Level-based layout (same algorithm as FlowVisualizer)
  const levels = new Map<string, number>();
  const visited = new Set<string>();

  function assignLevel(id: string): number {
    if (levels.has(id)) return levels.get(id)!;
    if (visited.has(id)) return 0;
    visited.add(id);

    const task = tasks.find((t) => t.id === id);
    if (!task || !task.depends_on || task.depends_on.length === 0) {
      levels.set(id, 0);
      return 0;
    }

    const maxParent = Math.max(
      ...task.depends_on.map((dep) => assignLevel(dep)),
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

  const nodes: GraphNode[] = [];
  for (const [level, ids] of byLevel) {
    ids.forEach((id, i) => {
      const task = tasks.find((t) => t.id === id)!;
      const data: DagNodeData = {
        specialist: task.specialist,
        mandate: task.mandate,
      };
      if (task.expected_output) {
        data.expectedOutput = task.expected_output;
      }
      nodes.push({
        id,
        position: {
          x: i * 250 - ((ids.length - 1) * 250) / 2,
          y: level * 150,
        },
        data: data as unknown as Record<string, unknown>,
      });
    });
  }

  const edges: GraphEdge[] = [];
  for (const task of tasks) {
    if (task.depends_on) {
      for (const dep of task.depends_on) {
        edges.push({
          id: `${dep}->${task.id}`,
          source: dep,
          target: task.id,
        });
      }
    }
  }

  return {
    nodes,
    edges,
    flowMeta: {
      kind: "dag",
      name: (doc.name as string) ?? "",
      description: doc.description as string | undefined,
    },
  };
}

function parseHandoffYaml(doc: Record<string, unknown>): GraphState {
  const rawNodes = (doc.nodes as YamlHandoffNode[]) ?? [];
  const rawEdges = (doc.edges as YamlHandoffEdge[]) ?? [];

  const nodes: GraphNode[] = rawNodes.map((n, i) => {
    const data: HandoffNodeData = {
      endpoint: n.endpoint,
      modelUrl: n.model_url,
      modelName: n.model_name,
      systemPrompt: n.system_prompt ?? "",
    };
    if (n.api_key) data.apiKey = n.api_key;
    if (n.max_iterations !== undefined) data.maxIterations = n.max_iterations;
    if (n.temperature !== undefined) data.temperature = n.temperature;
    if (n.max_tokens !== undefined) data.maxTokens = n.max_tokens;
    if (n.clearance) data.clearance = n.clearance;

    return {
      id: n.id,
      position: {
        x: (i % 3) * 280,
        y: Math.floor(i / 3) * 180,
      },
      data: data as unknown as Record<string, unknown>,
    };
  });

  const edges: GraphEdge[] = rawEdges.map((e, i) => ({
    id: `edge-${i}-${e.from}->${e.to}`,
    source: e.from,
    target: e.to,
    data: { description: e.description } as unknown as Record<string, unknown>,
  }));

  return {
    nodes,
    edges,
    flowMeta: {
      kind: "handoff",
      name: (doc.name as string) ?? "",
      description: doc.description as string | undefined,
      entry: doc.entry as string | undefined,
      maxHops: doc.max_hops as number | undefined,
    },
  };
}
