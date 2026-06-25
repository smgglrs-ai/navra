import React from "react";
import { Panel, PanelMain, PanelHeader, Title } from "@patternfly/react-core";

export interface PaletteItem {
  type: string;
  label: string;
  category: string;
  defaults: Record<string, unknown>;
}

export interface NodePaletteProps {
  kind: "dag" | "handoff";
  onDragStart?: (item: PaletteItem, event: React.DragEvent) => void;
}

const DAG_ITEMS: PaletteItem[] = [
  {
    type: "dag-task",
    label: "Task",
    category: "Tasks",
    defaults: {
      specialist: "",
      mandate: "",
      expectedOutput: "",
    },
  },
];

const HANDOFF_ITEMS: PaletteItem[] = [
  {
    type: "handoff-node",
    label: "Agent",
    category: "Agents",
    defaults: {
      endpoint: "http://localhost:9315/mcp",
      modelUrl: "http://localhost:11434/v1",
      modelName: "",
      systemPrompt: "",
    },
  },
];

export function NodePalette({ kind, onDragStart }: NodePaletteProps) {
  const items = kind === "dag" ? DAG_ITEMS : HANDOFF_ITEMS;

  const handleDragStart = (item: PaletteItem, event: React.DragEvent) => {
    event.dataTransfer.setData("application/json", JSON.stringify(item));
    event.dataTransfer.effectAllowed = "copy";
    onDragStart?.(item, event);
  };

  return (
    <div
      style={{
        width: 220,
        borderRight: "1px solid #d2d2d2",
        background: "#f5f5f5",
        fontFamily: "RedHatText, Overpass, sans-serif",
      }}
    >
      <Panel>
        <PanelHeader>
          <Title headingLevel="h3" size="md">
            Components
          </Title>
        </PanelHeader>
        <PanelMain>
          {items.map((item) => (
            <div
              key={item.type}
              draggable
              onDragStart={(e) => handleDragStart(item, e)}
              style={{
                padding: "8px 12px",
                margin: "4px 0",
                background: "#fff",
                border: "1px solid #d2d2d2",
                borderRadius: 4,
                cursor: "grab",
                fontSize: 13,
              }}
            >
              <div style={{ fontWeight: "bold" }}>{item.label}</div>
              <div style={{ fontSize: 11, color: "#6a6e73" }}>
                {item.category}
              </div>
            </div>
          ))}
        </PanelMain>
      </Panel>
    </div>
  );
}
