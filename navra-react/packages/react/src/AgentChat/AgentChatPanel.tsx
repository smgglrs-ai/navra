import React, { useRef, useState, useEffect } from "react";
import {
  Card,
  CardBody,
  CardTitle,
  CardHeader,
  TextArea,
  Button,
  Label,
  EmptyState,
  EmptyStateBody,
  Spinner,
  ExpandableSection,
  Split,
  SplitItem,
  Stack,
  StackItem,
} from "@patternfly/react-core";
import {
  useNavraAgent,
  type ToolCallState,
  type UseNavraAgentOptions,
} from "@navra/react-hooks";

export interface AgentChatPanelProps extends UseNavraAgentOptions {
  title?: string;
  placeholder?: string;
}

const STATUS_LABELS: Record<string, { text: string; color: "blue" | "green" | "red" | "grey" }> = {
  idle: { text: "Ready", color: "grey" },
  running: { text: "Running", color: "blue" },
  finished: { text: "Done", color: "green" },
  error: { text: "Error", color: "red" },
};

function formatDuration(ms?: number): string {
  if (ms === undefined) return "";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function ToolCallCard({ tc }: { tc: ToolCallState }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card isCompact isFlat>
      <CardHeader>
        <Split hasGutter>
          <SplitItem>
            <Label color={tc.status === "complete" ? "green" : "blue"}>
              {tc.name}
            </Label>
          </SplitItem>
          {tc.durationMs !== undefined && (
            <SplitItem>
              <Label color="grey">{formatDuration(tc.durationMs)}</Label>
            </SplitItem>
          )}
          <SplitItem isFilled />
          <SplitItem>
            {tc.status === "running" && <Spinner size="sm" />}
          </SplitItem>
        </Split>
      </CardHeader>
      <CardBody>
        <ExpandableSection
          toggleText={expanded ? "Hide details" : "Show details"}
          isExpanded={expanded}
          onToggle={(_e, isExpanded) => setExpanded(isExpanded)}
        >
          {tc.args && (
            <div>
              <strong>Arguments:</strong>
              <pre
                style={{
                  fontSize: "0.85em",
                  background: "var(--pf-t--global--background--color--secondary--default, #f0f0f0)",
                  padding: "8px",
                  borderRadius: "4px",
                  overflow: "auto",
                  maxHeight: "200px",
                }}
              >
                {tc.args}
              </pre>
            </div>
          )}
          {tc.result && (
            <div style={{ marginTop: "8px" }}>
              <strong>Result:</strong>
              <pre
                style={{
                  fontSize: "0.85em",
                  background: "var(--pf-t--global--background--color--secondary--default, #f0f0f0)",
                  padding: "8px",
                  borderRadius: "4px",
                  overflow: "auto",
                  maxHeight: "300px",
                }}
              >
                {tc.result}
              </pre>
            </div>
          )}
        </ExpandableSection>
      </CardBody>
    </Card>
  );
}

export function AgentChatPanel({
  title = "Agent Chat",
  placeholder = "Type a message...",
  ...hookOptions
}: AgentChatPanelProps) {
  const { state, send, reset, isRunning } = useNavraAgent(hookOptions);
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [state.messages, state.toolCalls.length]);

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed || isRunning) return;
    send(trimmed);
    setInput("");
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const statusLabel = STATUS_LABELS[state.status] ?? STATUS_LABELS.idle;

  return (
    <Card isFullHeight>
      <CardHeader>
        <Split hasGutter>
          <SplitItem>
            <CardTitle>{title}</CardTitle>
          </SplitItem>
          <SplitItem isFilled />
          <SplitItem>
            <Label color={statusLabel.color}>{statusLabel.text}</Label>
          </SplitItem>
          {state.status !== "idle" && (
            <SplitItem>
              <Button variant="link" onClick={reset} isDisabled={isRunning}>
                Reset
              </Button>
            </SplitItem>
          )}
        </Split>
      </CardHeader>
      <CardBody>
        <Stack hasGutter>
          <StackItem
            isFilled
            style={{ overflowY: "auto", maxHeight: "60vh", minHeight: "200px" }}
          >
            {state.status === "idle" && !state.messages && (
              <EmptyState>
                <EmptyStateBody>
                  Send a message to start a conversation with the agent.
                </EmptyStateBody>
              </EmptyState>
            )}

            {state.messages && (
              <div style={{ whiteSpace: "pre-wrap", fontFamily: "monospace" }}>
                {state.messages}
                {isRunning && <Spinner size="sm" style={{ marginLeft: "4px" }} />}
              </div>
            )}

            {state.toolCalls.length > 0 && (
              <Stack hasGutter style={{ marginTop: "16px" }}>
                {state.toolCalls.map((tc) => (
                  <StackItem key={tc.id}>
                    <ToolCallCard tc={tc} />
                  </StackItem>
                ))}
              </Stack>
            )}

            {state.error && (
              <div
                style={{
                  marginTop: "16px",
                  padding: "12px",
                  background: "var(--pf-t--global--color--status--danger--default, #c9190b)",
                  color: "white",
                  borderRadius: "4px",
                }}
              >
                {state.error}
              </div>
            )}

            <div ref={messagesEndRef} />
          </StackItem>

          <StackItem>
            <Split hasGutter>
              <SplitItem isFilled>
                <TextArea
                  value={input}
                  onChange={(_e, value) => setInput(value)}
                  onKeyDown={handleKeyDown}
                  placeholder={placeholder}
                  isDisabled={isRunning}
                  rows={2}
                  resizeOrientation="vertical"
                  aria-label="Agent prompt input"
                />
              </SplitItem>
              <SplitItem>
                <Button
                  variant="primary"
                  onClick={handleSend}
                  isDisabled={isRunning || !input.trim()}
                >
                  Send
                </Button>
              </SplitItem>
            </Split>
          </StackItem>
        </Stack>
      </CardBody>
    </Card>
  );
}
