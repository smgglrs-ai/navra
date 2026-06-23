import React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";

export interface EditorNodeData {
  label: string;
  nodeType: "dag" | "handoff";
  // DAG fields
  specialist?: string;
  mandate?: string;
  expectedOutput?: string;
  parameterCount?: number;
  // Handoff fields
  endpoint?: string;
  modelName?: string;
  systemPrompt?: string;
  // Common
  selected?: boolean;
  hasErrors?: boolean;
  [key: string]: unknown;
}

export function EditorNode({ data, selected }: NodeProps) {
  const nodeData = data as EditorNodeData;

  let borderColor = "#d2d2d2";
  if (nodeData.hasErrors) {
    borderColor = "#c9190b";
  } else if (selected) {
    borderColor = "#06c";
  }

  const displayInfo = nodeData.nodeType === "dag"
    ? nodeData.specialist
    : nodeData.modelName;

  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div
        style={{
          border: `2px solid ${borderColor}`,
          borderRadius: 8,
          padding: "8px 12px",
          background: "#fff",
          minWidth: 200,
          fontFamily: "RedHatText, Overpass, sans-serif",
          fontSize: 13,
        }}
      >
        <div style={{ fontWeight: "bold", marginBottom: 4 }}>
          {nodeData.label}
        </div>
        {displayInfo && (
          <div
            style={{
              fontSize: 11,
              color: "#6a6e73",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              maxWidth: 200,
              marginBottom: 4,
            }}
          >
            {displayInfo}
          </div>
        )}
        {nodeData.parameterCount !== undefined && nodeData.parameterCount > 0 && (
          <div
            style={{
              fontSize: 10,
              color: "#6a6e73",
              background: "#f0f0f0",
              borderRadius: 4,
              padding: "2px 6px",
              display: "inline-block",
            }}
          >
            {nodeData.parameterCount} params
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}
