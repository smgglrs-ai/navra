import React from "react";
import {
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  ToolbarGroup,
  Button,
  TextInput,
  Badge,
  ToggleGroup,
  ToggleGroupItem,
} from "@patternfly/react-core";
import { CodeIcon, SaveIcon, FolderOpenIcon } from "@patternfly/react-icons";

export interface FlowEditorToolbarProps {
  kind: "dag" | "handoff";
  flowName: string;
  onKindChange: (kind: "dag" | "handoff") => void;
  onFlowNameChange: (name: string) => void;
  onSave: () => void;
  onLoad: () => void;
  onToggleYaml: () => void;
  showYaml: boolean;
  validationErrorCount: number;
}

export function FlowEditorToolbar({
  kind,
  flowName,
  onKindChange,
  onFlowNameChange,
  onSave,
  onLoad,
  onToggleYaml,
  showYaml,
  validationErrorCount,
}: FlowEditorToolbarProps) {
  return (
    <Toolbar
      style={{
        height: 48,
        borderBottom: "1px solid #d2d2d2",
        fontFamily: "RedHatText, Overpass, sans-serif",
      }}
    >
      <ToolbarContent>
        <ToolbarGroup align={{ default: "alignStart" }}>
          <ToolbarItem>
            <TextInput
              value={flowName}
              onChange={(_event, value) => onFlowNameChange(value)}
              placeholder="Flow name"
              aria-label="Flow name"
              style={{ width: 200 }}
            />
          </ToolbarItem>
          <ToolbarItem>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <ToggleGroup aria-label="Flow kind">
                <ToggleGroupItem
                  text="DAG"
                  isSelected={kind === "dag"}
                  onChange={() => onKindChange("dag")}
                />
                <ToggleGroupItem
                  text="Handoff"
                  isSelected={kind === "handoff"}
                  onChange={() => onKindChange("handoff")}
                />
              </ToggleGroup>
              {validationErrorCount > 0 && (
                <Badge
                  style={{
                    background: "#c9190b",
                    color: "#fff",
                    fontSize: 11,
                  }}
                >
                  {validationErrorCount}
                </Badge>
              )}
            </div>
          </ToolbarItem>
        </ToolbarGroup>

        <ToolbarGroup align={{ default: "alignEnd" }}>
          <ToolbarItem>
            <Button variant="tertiary" onClick={onToggleYaml}>
              <CodeIcon style={{ marginRight: 4 }} />
              YAML
            </Button>
          </ToolbarItem>
          <ToolbarItem>
            <Button variant="secondary" onClick={onLoad}>
              <FolderOpenIcon style={{ marginRight: 4 }} />
              Load
            </Button>
          </ToolbarItem>
          <ToolbarItem>
            <Button variant="primary" onClick={onSave}>
              <SaveIcon style={{ marginRight: 4 }} />
              Save
            </Button>
          </ToolbarItem>
        </ToolbarGroup>
      </ToolbarContent>
    </Toolbar>
  );
}
