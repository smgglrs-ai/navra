import React, { useMemo, useState } from "react";
import {
  Button,
  Label,
  EmptyState,
  EmptyStateBody,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  TextInput,
  MenuToggle,
  Select,
  SelectOption,
} from "@patternfly/react-core";
import { Table, Thead, Tr, Th, Tbody, Td } from "@patternfly/react-table";
import {
  useToolEvents,
  type ToolEvent,
  type ToolOutcome,
} from "@navra/react-hooks";

export interface AgentActivityProps {
  baseUrl?: string;
  sessionId?: string;
  maxEvents?: number;
}

const OUTCOME_COLORS: Record<ToolOutcome, "green" | "red" | "orange" | "blue"> =
  {
    success: "green",
    denied: "red",
    error: "orange",
    pending: "blue",
  };

function formatDuration(ms?: number): string {
  if (ms === undefined) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString();
}

export function AgentActivity({
  baseUrl,
  sessionId,
  maxEvents = 500,
}: AgentActivityProps) {
  const { events, clear } = useToolEvents({
    baseUrl,
    sessionId,
    enabled: !!sessionId,
    maxEvents,
  });

  const [toolFilter, setToolFilter] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState<string>("all");
  const [outcomeOpen, setOutcomeOpen] = useState(false);

  const filtered = useMemo(() => {
    return events.filter((e) => {
      if (toolFilter && !e.toolName.includes(toolFilter)) return false;
      if (outcomeFilter !== "all" && e.outcome !== outcomeFilter) return false;
      return true;
    });
  }, [events, toolFilter, outcomeFilter]);

  const agents = useMemo(
    () => [...new Set(events.map((e) => e.agentName))],
    [events],
  );

  if (!sessionId) {
    return (
      <EmptyState titleText="No Session" headingLevel="h4">
        <EmptyStateBody>
          Connect to a navra session to see agent activity.
        </EmptyStateBody>
      </EmptyState>
    );
  }

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <TextInput
              placeholder="Filter by tool name"
              value={toolFilter}
              onChange={(_e, val) => setToolFilter(val)}
              aria-label="filter by tool"
            />
          </ToolbarItem>
          <ToolbarItem>
            <Select
              toggle={(toggleRef) => (
                <MenuToggle
                  ref={toggleRef}
                  onClick={() => setOutcomeOpen(!outcomeOpen)}
                  isExpanded={outcomeOpen}
                >
                  {outcomeFilter === "all" ? "All outcomes" : outcomeFilter}
                </MenuToggle>
              )}
              isOpen={outcomeOpen}
              onSelect={(_e, val) => {
                setOutcomeFilter(val as string);
                setOutcomeOpen(false);
              }}
              selected={outcomeFilter}
              onOpenChange={setOutcomeOpen}
            >
              <SelectOption value="all">All outcomes</SelectOption>
              <SelectOption value="success">Success</SelectOption>
              <SelectOption value="denied">Denied</SelectOption>
              <SelectOption value="error">Error</SelectOption>
              <SelectOption value="pending">Pending</SelectOption>
            </Select>
          </ToolbarItem>
          <ToolbarItem>
            <Button variant="plain" onClick={clear}>
              Clear
            </Button>
          </ToolbarItem>
          <ToolbarItem variant="label">
            {filtered.length} events
            {agents.length > 0 && ` · ${agents.length} agents`}
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>

      {filtered.length === 0 ? (
        <EmptyState variant="sm" titleText="No Events" headingLevel="h4">
          <EmptyStateBody>
            {events.length === 0
              ? "Waiting for tool call events…"
              : "No events match the current filter."}
          </EmptyStateBody>
        </EmptyState>
      ) : (
        <Table aria-label="Agent activity" variant="compact">
          <Thead>
            <Tr>
              <Th>Time</Th>
              <Th>Agent</Th>
              <Th>Tool</Th>
              <Th>Outcome</Th>
              <Th>Duration</Th>
              <Th>IFC Label</Th>
            </Tr>
          </Thead>
          <Tbody>
            {filtered.map((event: ToolEvent) => (
              <Tr key={event.id}>
                <Td>{formatTime(event.timestamp)}</Td>
                <Td>{event.agentName}</Td>
                <Td>
                  <code>{event.toolName}</code>
                </Td>
                <Td>
                  <Label color={OUTCOME_COLORS[event.outcome]}>
                    {event.outcome}
                  </Label>
                </Td>
                <Td>{formatDuration(event.durationMs)}</Td>
                <Td>
                  {event.ifcLabel ? (
                    <Label isCompact>{event.ifcLabel}</Label>
                  ) : (
                    "—"
                  )}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </>
  );
}
