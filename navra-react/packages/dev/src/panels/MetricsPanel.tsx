import React from "react";
import {
  Card,
  CardBody,
  CardTitle,
  Grid,
  GridItem,
  Content,
} from "@patternfly/react-core";
import { useNavraMetrics } from "@navra/react-hooks";

function MetricCard({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <Card isCompact>
      <CardTitle>{label}</CardTitle>
      <CardBody>
        <Content component="h2">{value.toLocaleString()}</Content>
      </CardBody>
    </Card>
  );
}

export function MetricsPanel() {
  const { metrics, error, loading } = useNavraMetrics({
    intervalMs: 3000,
  });

  if (loading) return <Content>Loading metrics...</Content>;
  if (error) {
    return (
      <Content>
        Could not connect to /metrics — is navra running?
        <br />
        <code>{error.message}</code>
      </Content>
    );
  }

  return (
    <Grid hasGutter>
      <GridItem span={3}>
        <MetricCard label="Tool Calls" value={metrics.toolCalls} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Errors" value={metrics.toolErrors} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Denied" value={metrics.toolDenied} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Approved" value={metrics.toolApproved} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Safety Triggers" value={metrics.safetyTriggers} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Safety Blocked" value={metrics.safetyBlocked} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="IFC Denials" value={metrics.ifcWriteDenials + metrics.ifcReadDenials} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Active Sessions" value={metrics.sessionsActive} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Input Tokens" value={metrics.inputTokens} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Output Tokens" value={metrics.outputTokens} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Model Refusals" value={metrics.modelRefusals} />
      </GridItem>
      <GridItem span={3}>
        <MetricCard label="Integrity Alerts" value={metrics.integrityAlerts} />
      </GridItem>
    </Grid>
  );
}
