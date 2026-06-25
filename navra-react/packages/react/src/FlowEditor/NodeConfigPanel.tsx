import React from "react";
import {
  Panel,
  PanelMain,
  PanelHeader,
  Title,
  Form,
  FormGroup,
  TextInput,
  TextArea,
  Button,
  Alert,
} from "@patternfly/react-core";
import { TimesIcon } from "@patternfly/react-icons";
import type { ValidationError } from "@navra/react-hooks";

export interface NodeConfigPanelProps {
  node: { id: string; data: Record<string, unknown> } | null;
  kind: "dag" | "handoff";
  validationErrors?: ValidationError[];
  onChange: (nodeId: string, data: Record<string, unknown>) => void;
  onClose: () => void;
}

export function NodeConfigPanel({
  node,
  kind,
  validationErrors = [],
  onChange,
  onClose,
}: NodeConfigPanelProps) {
  if (!node) {
    return null;
  }

  const nodeErrors = validationErrors.filter(
    (err) => err.nodeIds?.includes(node.id),
  );

  const handleFieldChange = (field: string, value: unknown) => {
    onChange(node.id, { ...node.data, [field]: value });
  };

  return (
    <div
      style={{
        width: 320,
        borderLeft: "1px solid #d2d2d2",
        background: "#fff",
        fontFamily: "RedHatText, Overpass, sans-serif",
        overflow: "auto",
      }}
    >
      <Panel>
        <PanelHeader>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <Title headingLevel="h3" size="md">
              Configure Node
            </Title>
            <Button variant="plain" onClick={onClose}>
              <TimesIcon />
            </Button>
          </div>
        </PanelHeader>
        <PanelMain>
          {nodeErrors.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              {nodeErrors.map((err) => (
                <Alert
                  key={err.id}
                  variant="danger"
                  isInline
                  title={err.message}
                  style={{ marginBottom: 8 }}
                />
              ))}
            </div>
          )}
          <Form>
            <FormGroup label="Name" isRequired fieldId="node-name">
              <TextInput
                id="node-name"
                value={(node.data.label as string) || ""}
                onChange={(_event, value) => handleFieldChange("label", value)}
              />
            </FormGroup>

            {kind === "dag" ? (
              <>
                <FormGroup
                  label="Specialist"
                  isRequired
                  fieldId="node-specialist"
                >
                  <TextInput
                    id="node-specialist"
                    value={(node.data.specialist as string) || ""}
                    onChange={(_event, value) =>
                      handleFieldChange("specialist", value)
                    }
                  />
                </FormGroup>
                <FormGroup label="Mandate" isRequired fieldId="node-mandate">
                  <TextArea
                    id="node-mandate"
                    value={(node.data.mandate as string) || ""}
                    onChange={(_event, value) =>
                      handleFieldChange("mandate", value)
                    }
                    rows={4}
                  />
                </FormGroup>
                <FormGroup
                  label="Expected Output"
                  fieldId="node-expected-output"
                >
                  <TextArea
                    id="node-expected-output"
                    value={(node.data.expectedOutput as string) || ""}
                    onChange={(_event, value) =>
                      handleFieldChange("expectedOutput", value)
                    }
                    rows={3}
                  />
                </FormGroup>
              </>
            ) : (
              <>
                <FormGroup label="Endpoint" isRequired fieldId="node-endpoint">
                  <TextInput
                    id="node-endpoint"
                    value={(node.data.endpoint as string) || ""}
                    onChange={(_event, value) =>
                      handleFieldChange("endpoint", value)
                    }
                  />
                </FormGroup>
                <FormGroup
                  label="Model URL"
                  isRequired
                  fieldId="node-model-url"
                >
                  <TextInput
                    id="node-model-url"
                    value={(node.data.modelUrl as string) || ""}
                    onChange={(_event, value) =>
                      handleFieldChange("modelUrl", value)
                    }
                  />
                </FormGroup>
                <FormGroup
                  label="Model Name"
                  isRequired
                  fieldId="node-model-name"
                >
                  <TextInput
                    id="node-model-name"
                    value={(node.data.modelName as string) || ""}
                    onChange={(_event, value) =>
                      handleFieldChange("modelName", value)
                    }
                  />
                </FormGroup>
                <FormGroup
                  label="System Prompt"
                  isRequired
                  fieldId="node-system-prompt"
                >
                  <TextArea
                    id="node-system-prompt"
                    value={(node.data.systemPrompt as string) || ""}
                    onChange={(_event, value) =>
                      handleFieldChange("systemPrompt", value)
                    }
                    rows={6}
                  />
                </FormGroup>
                <FormGroup label="Temperature" fieldId="node-temperature">
                  <TextInput
                    id="node-temperature"
                    type="number"
                    value={
                      node.data.temperature !== undefined
                        ? String(node.data.temperature)
                        : ""
                    }
                    onChange={(_event, value) =>
                      handleFieldChange(
                        "temperature",
                        value ? Number.parseFloat(value) : undefined,
                      )
                    }
                  />
                </FormGroup>
                <FormGroup label="Max Tokens" fieldId="node-max-tokens">
                  <TextInput
                    id="node-max-tokens"
                    type="number"
                    value={
                      node.data.maxTokens !== undefined
                        ? String(node.data.maxTokens)
                        : ""
                    }
                    onChange={(_event, value) =>
                      handleFieldChange(
                        "maxTokens",
                        value ? Number.parseInt(value, 10) : undefined,
                      )
                    }
                  />
                </FormGroup>
              </>
            )}
          </Form>
        </PanelMain>
      </Panel>
    </div>
  );
}
