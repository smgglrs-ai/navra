import React from "react";
import type { Meta, StoryObj } from "@storybook/react";
import { useNavraMetrics } from "./useNavraMetrics";

function MetricsDisplay() {
  const { metrics, error, loading } = useNavraMetrics({
    url: "/metrics",
    intervalMs: 5000,
  });

  if (loading) return <div>Loading metrics...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <table>
      <thead>
        <tr>
          <th>Metric</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {Object.entries(metrics).map(([key, value]) => (
          <tr key={key}>
            <td>{key}</td>
            <td>{value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const meta: Meta = {
  title: "Hooks/useNavraMetrics",
  component: MetricsDisplay,
};

export default meta;

type Story = StoryObj<typeof MetricsDisplay>;

export const Default: Story = {};
