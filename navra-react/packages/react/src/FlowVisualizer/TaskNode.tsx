import React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Label } from "@patternfly/react-core";
import type { FlowTaskStatus } from "@navra/react-hooks";

export interface TaskNodeData {
  specialist: string;
  mandate: string;
  status: FlowTaskStatus;
  validationScore?: number;
  tokenUsage?: { prompt: number; completion: number };
  [key: string]: unknown;
}

const STATUS_COLORS: Record<FlowTaskStatus, "grey" | "blue" | "green" | "red" | "orange" | "teal"> = {
  pending: "grey",
  ready: "teal",
  running: "blue",
  complete: "green",
  failed: "red",
  skipped: "orange",
};

const STATUS_BORDERS: Record<FlowTaskStatus, string> = {
  pending: "#d2d2d2",
  ready: "#009596",
  running: "#06c",
  complete: "#3e8635",
  failed: "#c9190b",
  skipped: "#f0ab00",
};

export function TaskNode({ data }: NodeProps) {
  const nodeData = data as TaskNodeData;
  const borderColor = STATUS_BORDERS[nodeData.status] ?? "#d2d2d2";

  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div
        style={{
          border: `2px solid ${borderColor}`,
          borderRadius: 8,
          padding: "8px 12px",
          background: "#fff",
          minWidth: 180,
          fontFamily: "RedHatText, Overpass, sans-serif",
          fontSize: 13,
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 4,
          }}
        >
          <strong>{nodeData.specialist}</strong>
          <Label isCompact color={STATUS_COLORS[nodeData.status]}>
            {nodeData.status}
          </Label>
        </div>
        <div
          style={{
            fontSize: 11,
            color: "#6a6e73",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            maxWidth: 200,
          }}
        >
          {nodeData.mandate}
        </div>
        {nodeData.validationScore !== undefined && (
          <div style={{ marginTop: 4 }}>
            <div
              style={{
                height: 4,
                background: "#f0f0f0",
                borderRadius: 2,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${nodeData.validationScore}%`,
                  height: "100%",
                  background:
                    nodeData.validationScore >= 70 ? "#3e8635" : "#c9190b",
                  borderRadius: 2,
                }}
              />
            </div>
            <span style={{ fontSize: 10, color: "#6a6e73" }}>
              {nodeData.validationScore.toFixed(0)}/100
            </span>
          </div>
        )}
        {nodeData.tokenUsage && (
          <div style={{ fontSize: 10, color: "#6a6e73", marginTop: 2 }}>
            {nodeData.tokenUsage.prompt + nodeData.tokenUsage.completion} tokens
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}
