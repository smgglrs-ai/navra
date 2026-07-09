export interface ServerStatus {
  name: string;
  version: string;
  status: string;
  models: string[];
  personas: string[];
  crates: number;
}

export interface ModelInfo {
  name: string;
  task: string;
  backend: string;
  source: string | null;
  runtime: string | null;
  context_size: number | null;
}

export interface AgentInfo {
  name: string;
  permissions: string;
  ring: number | null;
  capability_token: boolean;
  did: string | null;
  safety: string | null;
  operations: string[] | null;
  taint: string;
}

export interface FlowInfo {
  name: string;
  path: string;
  tasks: number;
}

export interface FlowRunSummary {
  flow_id: string;
  name: string;
  status: string;
  elapsed_secs: number;
  node_count: number;
}

export interface FlowGraph {
  flow_id: string;
  name: string;
  status: string;
  nodes: FlowGraphNode[];
  edges: FlowGraphEdge[];
}

export interface FlowGraphNode {
  id: string;
  label: string;
  status: string;
  duration_ms?: number;
}

export interface FlowGraphEdge {
  source: string;
  target: string;
}

export interface ProcessSnapshot {
  name: string;
  permissions: string;
  did: string | null;
  ring: number | null;
  call_count: number;
  denied_count: number;
  uptime_secs: number;
  idle_secs: number;
  active_calls: string[];
}

export interface BlackboxEntry {
  seq: number;
  timestamp_ms: number;
  agent_name: string;
  agent_permissions: string;
  session_id: string;
  tool_name: string;
  tool_args: string;
  tool_result: string;
  outcome: string;
  duration_us: number;
  ifc_label: string;
}

export interface AuditResponse {
  entries: BlackboxEntry[];
  total: number;
}

export interface SafetyMetrics {
  total_scans: number;
  pii_detected: number;
  pii_redacted: number;
  pii_blocked: number;
  by_category: Record<string, number>;
}

export interface PermissionSet {
  ring?: number;
  allow?: string[];
  deny?: string[];
  operations?: string[];
  safety?: string;
  tool_rules?: ToolRule[];
}

export interface ToolRule {
  tool: string;
  policy: 'Allow' | 'Deny' | 'Approve';
}

export interface ChatEvent {
  type: 'text' | 'tool_call' | 'done';
  content?: string;
  name?: string;
  arguments?: string;
  result?: string;
  usage?: { input_tokens: number; output_tokens: number };
}
