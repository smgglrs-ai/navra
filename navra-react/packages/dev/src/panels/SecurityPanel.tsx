import React from "react";
import { SecurityDashboard } from "@navra/react";

export function SecurityPanel() {
  return <SecurityDashboard intervalMs={3000} maxSnapshots={60} />;
}
