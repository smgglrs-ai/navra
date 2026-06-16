import React from "react";
import {
  Card,
  CardBody,
  CardTitle,
  Grid,
  GridItem,
  Content,
  EmptyState,
  EmptyStateBody,
} from "@patternfly/react-core";
import {
  Chart,
  ChartArea,
  ChartAxis,
  ChartGroup,
  ChartVoronoiContainer,
} from "@patternfly/react-charts/victory";
import {
  useMetricsHistory,
  type MetricsSnapshot,
  type NavraMetrics,
} from "@navra/react-hooks";

export interface SecurityDashboardProps {
  url?: string;
  intervalMs?: number;
  maxSnapshots?: number;
}

interface StatCardProps {
  title: string;
  value: number;
  color?: string;
}

function StatCard({ title, value, color }: StatCardProps) {
  return (
    <Card isCompact>
      <CardTitle>{title}</CardTitle>
      <CardBody>
        <Content
          component="h2"
          style={color ? { color } : undefined}
        >
          {value.toLocaleString()}
        </Content>
      </CardBody>
    </Card>
  );
}

interface TimeSeriesChartProps {
  title: string;
  history: MetricsSnapshot[];
  series: { key: keyof NavraMetrics; label: string; color: string }[];
  height?: number;
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function TimeSeriesChart({
  title,
  history,
  series,
  height = 200,
}: TimeSeriesChartProps) {
  if (history.length < 2) {
    return (
      <Card>
        <CardTitle>{title}</CardTitle>
        <CardBody>
          <Content component="small">Collecting data...</Content>
        </CardBody>
      </Card>
    );
  }

  const tickCount = Math.min(history.length, 5);
  const tickIndices = Array.from({ length: tickCount }, (_, i) =>
    Math.floor((i / (tickCount - 1)) * (history.length - 1)),
  );

  return (
    <Card>
      <CardTitle>{title}</CardTitle>
      <CardBody>
        <div style={{ height }}>
          <Chart
            height={height}
            padding={{ top: 10, right: 20, bottom: 40, left: 50 }}
            containerComponent={
              <ChartVoronoiContainer
                labels={({ datum }: { datum: { y: number } }) =>
                  `${datum.y}`
                }
              />
            }
          >
            <ChartAxis
              tickValues={tickIndices}
              tickFormat={(i: number) =>
                history[i] ? formatTime(history[i].timestamp) : ""
              }
            />
            <ChartAxis dependentAxis />
            <ChartGroup>
              {series.map((s) => (
                <ChartArea
                  key={s.key}
                  data={history.map((snap, i) => ({
                    x: i,
                    y: snap.metrics[s.key] as number,
                    name: s.label,
                  }))}
                  style={{
                    data: {
                      fill: s.color,
                      fillOpacity: 0.2,
                      stroke: s.color,
                    },
                  }}
                />
              ))}
            </ChartGroup>
          </Chart>
        </div>
      </CardBody>
    </Card>
  );
}

export function SecurityDashboard({
  url,
  intervalMs = 5000,
  maxSnapshots = 60,
}: SecurityDashboardProps) {
  const { current, history, error, loading } = useMetricsHistory({
    url,
    intervalMs,
    maxSnapshots,
  });

  if (loading) {
    return <Content>Loading security metrics...</Content>;
  }

  if (error) {
    return (
      <EmptyState
        variant="sm"
        titleText="Connection Error"
        headingLevel="h4"
      >
        <EmptyStateBody>
          Could not connect to metrics endpoint: {error.message}
        </EmptyStateBody>
      </EmptyState>
    );
  }

  return (
    <Grid hasGutter>
      <GridItem span={3}>
        <StatCard title="Tool Calls" value={current.toolCalls} />
      </GridItem>
      <GridItem span={3}>
        <StatCard
          title="Blocked"
          value={current.safetyBlocked + current.toolDenied}
          color="#c9190b"
        />
      </GridItem>
      <GridItem span={3}>
        <StatCard
          title="IFC Violations"
          value={current.ifcWriteDenials + current.ifcReadDenials}
          color="#f0ab00"
        />
      </GridItem>
      <GridItem span={3}>
        <StatCard
          title="Integrity Alerts"
          value={current.integrityAlerts}
          color={current.integrityMalicious > 0 ? "#c9190b" : "#6a6e73"}
        />
      </GridItem>

      <GridItem span={6}>
        <TimeSeriesChart
          title="Tool Calls & Denials"
          history={history}
          series={[
            { key: "toolCalls", label: "Calls", color: "#06c" },
            { key: "toolDenied", label: "Denied", color: "#c9190b" },
            { key: "toolApproved", label: "Approved", color: "#3e8635" },
          ]}
        />
      </GridItem>
      <GridItem span={6}>
        <TimeSeriesChart
          title="Safety & IFC"
          history={history}
          series={[
            { key: "safetyTriggers", label: "Triggers", color: "#f0ab00" },
            { key: "safetyBlocked", label: "Blocked", color: "#c9190b" },
            {
              key: "ifcTaintElevations",
              label: "Taint Elevations",
              color: "#8481dd",
            },
          ]}
        />
      </GridItem>

      <GridItem span={4}>
        <StatCard title="Active Sessions" value={current.sessionsActive} />
      </GridItem>
      <GridItem span={4}>
        <StatCard title="Auth Failures" value={current.authFailures} />
      </GridItem>
      <GridItem span={4}>
        <StatCard
          title="Leakage Blocks"
          value={
            current.leakageSimilarityBlocks + current.leakageSemanticBlocks
          }
        />
      </GridItem>
    </Grid>
  );
}
