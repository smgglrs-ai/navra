import { describe, expect, it } from "vitest";
import { graphToYaml, yamlToGraph } from "./useYamlSync";

const DAG_YAML = `kind: dag
name: security-audit
description: Audit a project for security vulnerabilities
tasks:
  - id: scan
    specialist: security_auditor
    mandate: Scan target for vulnerabilities
    expected_output: List of findings with CWE IDs
  - id: synthesize
    specialist: analyst
    mandate: Synthesize scan findings into a prioritized report
    depends_on:
      - scan
`;

const HANDOFF_YAML = `kind: handoff
name: support-triage
description: Customer support triage flow
entry: router
max_hops: 10
nodes:
  - id: router
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: Route support requests.
  - id: billing
    endpoint: "http://localhost:9315/mcp"
    model_url: "http://localhost:11434/v1"
    model_name: "qwen2.5:0.5b"
    system_prompt: Handle billing inquiries.
edges:
  - from: router
    to: billing
    description: Customer has a billing question
`;

describe("yamlToGraph", () => {
  it("parses DAG YAML into graph state", () => {
    const result = yamlToGraph(DAG_YAML);
    expect(result.flowMeta.kind).toBe("dag");
    expect(result.flowMeta.name).toBe("security-audit");
    expect(result.flowMeta.description).toBe(
      "Audit a project for security vulnerabilities",
    );
    expect(result.nodes).toHaveLength(2);
    expect(result.edges).toHaveLength(1);

    const scan = result.nodes.find((n) => n.id === "scan");
    expect(scan).toBeDefined();
    expect(scan!.data.specialist).toBe("security_auditor");
    expect(scan!.data.mandate).toBe("Scan target for vulnerabilities");

    const edge = result.edges[0];
    expect(edge.source).toBe("scan");
    expect(edge.target).toBe("synthesize");
  });

  it("parses handoff YAML into graph state", () => {
    const result = yamlToGraph(HANDOFF_YAML);
    expect(result.flowMeta.kind).toBe("handoff");
    expect(result.flowMeta.name).toBe("support-triage");
    expect(result.flowMeta.entry).toBe("router");
    expect(result.flowMeta.maxHops).toBe(10);
    expect(result.nodes).toHaveLength(2);
    expect(result.edges).toHaveLength(1);

    const router = result.nodes.find((n) => n.id === "router");
    expect(router).toBeDefined();
    expect(router!.data.modelName).toBe("qwen2.5:0.5b");
    expect(router!.data.endpoint).toBe("http://localhost:9315/mcp");
  });

  it("returns empty state for invalid YAML", () => {
    const result = yamlToGraph("not: valid: yaml: [");
    expect(result.nodes).toHaveLength(0);
  });

  it("returns empty state for empty string", () => {
    const result = yamlToGraph("");
    expect(result.nodes).toHaveLength(0);
    expect(result.flowMeta.kind).toBe("dag");
  });
});

describe("graphToYaml", () => {
  it("produces valid DAG YAML", () => {
    const nodes = [
      {
        id: "task1",
        position: { x: 0, y: 0 },
        data: { specialist: "dev", mandate: "Write code" },
      },
      {
        id: "task2",
        position: { x: 0, y: 150 },
        data: { specialist: "reviewer", mandate: "Review code" },
      },
    ];
    const edges = [
      { id: "e1", source: "task1", target: "task2" },
    ];
    const result = graphToYaml(nodes, edges, {
      kind: "dag",
      name: "test-flow",
    });

    expect(result).toContain("kind: dag");
    expect(result).toContain("name: test-flow");
    expect(result).toContain("specialist: dev");
    expect(result).toContain("specialist: reviewer");
    expect(result).toContain("depends_on:");
  });

  it("produces valid handoff YAML", () => {
    const nodes = [
      {
        id: "agent1",
        position: { x: 0, y: 0 },
        data: {
          endpoint: "http://localhost:9315/mcp",
          modelUrl: "http://localhost:11434/v1",
          modelName: "test-model",
          systemPrompt: "You are agent 1",
        },
      },
    ];
    const edges: Array<{ id: string; source: string; target: string }> = [];
    const result = graphToYaml(nodes, edges, {
      kind: "handoff",
      name: "test-handoff",
      entry: "agent1",
    });

    expect(result).toContain("kind: handoff");
    expect(result).toContain("entry: agent1");
    expect(result).toContain("model_name: test-model");
    expect(result).toContain("system_prompt: You are agent 1");
  });
});

describe("roundtrip", () => {
  it("DAG: graphToYaml -> yamlToGraph preserves structure", () => {
    const original = yamlToGraph(DAG_YAML);
    const yamlStr = graphToYaml(
      original.nodes,
      original.edges,
      original.flowMeta,
    );
    const roundtripped = yamlToGraph(yamlStr);

    expect(roundtripped.flowMeta.kind).toBe(original.flowMeta.kind);
    expect(roundtripped.flowMeta.name).toBe(original.flowMeta.name);
    expect(roundtripped.nodes).toHaveLength(original.nodes.length);
    expect(roundtripped.edges).toHaveLength(original.edges.length);

    for (const origNode of original.nodes) {
      const found = roundtripped.nodes.find((n) => n.id === origNode.id);
      expect(found).toBeDefined();
      expect(found!.data.specialist).toBe(origNode.data.specialist);
      expect(found!.data.mandate).toBe(origNode.data.mandate);
    }
  });

  it("Handoff: graphToYaml -> yamlToGraph preserves structure", () => {
    const original = yamlToGraph(HANDOFF_YAML);
    const yamlStr = graphToYaml(
      original.nodes,
      original.edges,
      original.flowMeta,
    );
    const roundtripped = yamlToGraph(yamlStr);

    expect(roundtripped.flowMeta.kind).toBe("handoff");
    expect(roundtripped.flowMeta.name).toBe(original.flowMeta.name);
    expect(roundtripped.flowMeta.entry).toBe(original.flowMeta.entry);
    expect(roundtripped.nodes).toHaveLength(original.nodes.length);
    expect(roundtripped.edges).toHaveLength(original.edges.length);
  });
});
