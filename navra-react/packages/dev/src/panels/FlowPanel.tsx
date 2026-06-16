import React, { useMemo } from "react";
import { FlowVisualizer } from "@navra/react";
import type { FlowDefinition, FlowState } from "@navra/react-hooks";

const MOCK_DEFINITION: FlowDefinition = {
  tasks: [
    {
      id: "gather",
      specialist: "researcher",
      mandate: "Gather relevant context from codebase and docs",
      dependsOn: [],
    },
    {
      id: "analyze",
      specialist: "analyst",
      mandate: "Analyze gathered context for security implications",
      dependsOn: ["gather"],
    },
    {
      id: "review",
      specialist: "reviewer",
      mandate: "Cross-validate analysis against known vulnerability patterns",
      dependsOn: ["analyze"],
    },
    {
      id: "draft",
      specialist: "writer",
      mandate: "Draft security assessment report with recommendations",
      dependsOn: ["analyze"],
    },
    {
      id: "finalize",
      specialist: "lead",
      mandate: "Merge review findings into final report, assign severity ratings",
      dependsOn: ["review", "draft"],
    },
  ],
};

const MOCK_STATE: FlowState = {
  tasks: new Map([
    [
      "gather",
      {
        id: "gather",
        specialist: "researcher",
        mandate: "Gather relevant context from codebase and docs",
        status: "complete",
        dependsOn: [],
        tokenUsage: { prompt: 1200, completion: 800 },
      },
    ],
    [
      "analyze",
      {
        id: "analyze",
        specialist: "analyst",
        mandate: "Analyze gathered context for security implications",
        status: "complete",
        dependsOn: ["gather"],
        validationScore: 85,
        tokenUsage: { prompt: 2400, completion: 1600 },
      },
    ],
    [
      "review",
      {
        id: "review",
        specialist: "reviewer",
        mandate: "Cross-validate analysis against known vulnerability patterns",
        status: "running",
        dependsOn: ["analyze"],
      },
    ],
    [
      "draft",
      {
        id: "draft",
        specialist: "writer",
        mandate: "Draft security assessment report with recommendations",
        status: "complete",
        dependsOn: ["analyze"],
        validationScore: 62,
        tokenUsage: { prompt: 3000, completion: 2200 },
      },
    ],
    [
      "finalize",
      {
        id: "finalize",
        specialist: "lead",
        mandate: "Merge review findings into final report, assign severity ratings",
        status: "pending",
        dependsOn: ["review", "draft"],
      },
    ],
  ]),
  backEdges: [
    { from: "draft", to: "analyze", iteration: 1 },
  ],
  completed: false,
};

export function FlowPanel() {
  return (
    <FlowVisualizer
      definition={MOCK_DEFINITION}
      state={MOCK_STATE}
      height={600}
    />
  );
}
