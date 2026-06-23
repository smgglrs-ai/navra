import { describe, expect, it } from "vitest";
import { validateFlow } from "./useFlowValidation";

describe("validateFlow", () => {
  it("valid DAG passes validation", () => {
    const nodes = [
      { id: "a", data: { specialist: "dev", mandate: "Do work" } },
      { id: "b", data: { specialist: "reviewer", mandate: "Review" } },
    ];
    const edges = [{ source: "a", target: "b" }];
    const errors = validateFlow(nodes, edges, "dag");
    const criticalErrors = errors.filter((e) => e.severity === "error");
    expect(criticalErrors).toHaveLength(0);
  });

  it("detects cycles in DAG", () => {
    const nodes = [
      { id: "a", data: { specialist: "dev", mandate: "Do" } },
      { id: "b", data: { specialist: "dev", mandate: "Do" } },
    ];
    const edges = [
      { source: "a", target: "b" },
      { source: "b", target: "a" },
    ];
    const errors = validateFlow(nodes, edges, "dag");
    expect(errors.some((e) => e.id === "cycle-detected")).toBe(true);
  });

  it("detects missing specialist field", () => {
    const nodes = [{ id: "a", data: { mandate: "Do work" } }];
    const errors = validateFlow(nodes, [], "dag");
    expect(
      errors.some((e) => e.id === "missing-specialist-a"),
    ).toBe(true);
  });

  it("detects missing mandate field", () => {
    const nodes = [{ id: "a", data: { specialist: "dev" } }];
    const errors = validateFlow(nodes, [], "dag");
    expect(
      errors.some((e) => e.id === "missing-mandate-a"),
    ).toBe(true);
  });

  it("detects duplicate node IDs", () => {
    const nodes = [
      { id: "x", data: { specialist: "a", mandate: "b" } },
      { id: "x", data: { specialist: "c", mandate: "d" } },
    ];
    const errors = validateFlow(nodes, [], "dag");
    expect(errors.some((e) => e.id === "duplicate-x")).toBe(true);
  });

  it("warns on empty graph", () => {
    const errors = validateFlow([], [], "dag");
    expect(errors.some((e) => e.id === "empty-graph")).toBe(true);
    expect(errors[0].severity).toBe("warning");
  });

  it("detects dangling edge source", () => {
    const nodes = [{ id: "a", data: { specialist: "d", mandate: "m" } }];
    const edges = [{ source: "nonexistent", target: "a" }];
    const errors = validateFlow(nodes, edges, "dag");
    expect(
      errors.some(
        (e) => e.id === "dangling-source-nonexistent-a",
      ),
    ).toBe(true);
  });

  it("detects dangling edge target", () => {
    const nodes = [{ id: "a", data: { specialist: "d", mandate: "m" } }];
    const edges = [{ source: "a", target: "nonexistent" }];
    const errors = validateFlow(nodes, edges, "dag");
    expect(
      errors.some(
        (e) => e.id === "dangling-target-a-nonexistent",
      ),
    ).toBe(true);
  });

  it("warns on isolated nodes", () => {
    const nodes = [
      { id: "a", data: { specialist: "d", mandate: "m" } },
      { id: "b", data: { specialist: "d", mandate: "m" } },
    ];
    // No edges — both are isolated
    const errors = validateFlow(nodes, [], "dag");
    const unreachable = errors.filter((e) => e.id.startsWith("unreachable-"));
    expect(unreachable.length).toBe(2);
    expect(unreachable[0].severity).toBe("warning");
  });

  it("valid handoff passes validation", () => {
    const nodes = [
      {
        id: "router",
        data: {
          endpoint: "http://localhost:9315/mcp",
          modelUrl: "http://localhost:11434/v1",
          modelName: "test",
        },
      },
    ];
    const errors = validateFlow(nodes, [], "handoff", "router");
    const criticalErrors = errors.filter((e) => e.severity === "error");
    expect(criticalErrors).toHaveLength(0);
  });

  it("handoff missing entry produces error", () => {
    const nodes = [
      {
        id: "a",
        data: {
          endpoint: "http://x",
          modelUrl: "http://x",
          modelName: "m",
        },
      },
    ];
    const errors = validateFlow(nodes, [], "handoff");
    expect(errors.some((e) => e.id === "missing-entry")).toBe(true);
  });

  it("handoff invalid entry produces error", () => {
    const nodes = [
      {
        id: "a",
        data: {
          endpoint: "http://x",
          modelUrl: "http://x",
          modelName: "m",
        },
      },
    ];
    const errors = validateFlow(nodes, [], "handoff", "nonexistent");
    expect(errors.some((e) => e.id === "invalid-entry")).toBe(true);
  });

  it("handoff missing required fields produces errors", () => {
    const nodes = [{ id: "a", data: {} }];
    const errors = validateFlow(nodes, [], "handoff", "a");
    expect(errors.some((e) => e.id === "missing-endpoint-a")).toBe(true);
    expect(errors.some((e) => e.id === "missing-modelUrl-a")).toBe(true);
    expect(errors.some((e) => e.id === "missing-modelName-a")).toBe(true);
  });
});
