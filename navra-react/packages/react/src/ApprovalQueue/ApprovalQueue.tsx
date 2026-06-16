import React, { useCallback } from "react";
import {
  Button,
  Label,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
} from "@patternfly/react-core";
import { CheckIcon, TimesIcon, ShieldAltIcon } from "@patternfly/react-icons";
import { Table, Thead, Tr, Th, Tbody, Td } from "@patternfly/react-table";
import { useApprovalQueue, type PendingApproval } from "@navra/react-hooks";

export interface ApprovalQueueProps {
  baseUrl?: string;
  sessionId?: string;
  maxArgumentLength?: number;
}

function redactArguments(summary: string, maxLength: number): string {
  const redacted = summary.replace(
    /(password|secret|token|key|credential|auth)['"]*\s*[:=]\s*['"][^'"]+['"]/gi,
    "$1: [REDACTED]",
  );
  if (redacted.length <= maxLength) return redacted;
  return redacted.slice(0, maxLength) + "…";
}

function timeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

export function ApprovalQueue({
  baseUrl,
  sessionId,
  maxArgumentLength = 120,
}: ApprovalQueueProps) {
  const { pending, approve, deny, error } = useApprovalQueue({
    baseUrl,
    sessionId,
    enabled: !!sessionId,
  });

  const handleApprove = useCallback(
    (requestId: string) => {
      approve(requestId);
    },
    [approve],
  );

  const handleDeny = useCallback(
    (requestId: string) => {
      deny(requestId, "Denied by operator");
    },
    [deny],
  );

  if (!sessionId) {
    return (
      <EmptyState
        titleText="No Session"
        icon={ShieldAltIcon}
        headingLevel="h4"
      >
        <EmptyStateBody>
          Connect to a navra session to see pending approvals.
        </EmptyStateBody>
      </EmptyState>
    );
  }

  if (error) {
    return (
      <EmptyState variant="sm" titleText="Connection Error" headingLevel="h4">
        <EmptyStateBody>{error.message}</EmptyStateBody>
      </EmptyState>
    );
  }

  if (pending.length === 0) {
    return (
      <EmptyState
        variant="sm"
        titleText="No Pending Approvals"
        icon={ShieldAltIcon}
        headingLevel="h4"
      >
        <EmptyStateBody>
          Approvals will appear here when agents request high-risk operations.
        </EmptyStateBody>
      </EmptyState>
    );
  }

  return (
    <Table aria-label="Pending approvals" variant="compact">
      <Thead>
        <Tr>
          <Th>Tool</Th>
          <Th>Agent</Th>
          <Th>Arguments</Th>
          <Th>Time</Th>
          <Th>Actions</Th>
        </Tr>
      </Thead>
      <Tbody>
        {pending.map((approval: PendingApproval) => (
          <Tr key={approval.requestId}>
            <Td>
              <Label color="orange">{approval.toolName}</Label>
            </Td>
            <Td>{approval.agentName}</Td>
            <Td>
              <code>
                {redactArguments(approval.argumentsSummary, maxArgumentLength)}
              </code>
            </Td>
            <Td>{timeAgo(approval.createdAt)}</Td>
            <Td>
              <Flex>
                <FlexItem>
                  <Button
                    variant="primary"
                    size="sm"
                    icon={<CheckIcon />}
                    onClick={() => handleApprove(approval.requestId)}
                  >
                    Approve
                  </Button>
                </FlexItem>
                <FlexItem>
                  <Button
                    variant="danger"
                    size="sm"
                    icon={<TimesIcon />}
                    onClick={() => handleDeny(approval.requestId)}
                  >
                    Deny
                  </Button>
                </FlexItem>
              </Flex>
            </Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
  );
}
