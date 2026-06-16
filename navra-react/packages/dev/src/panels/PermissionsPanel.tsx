import React, { useState } from "react";
import {
  PermissionEditor,
  type PermissionConfig,
} from "@navra/react";

const MOCK_CONFIG: PermissionConfig = {
  admin: {
    ring: 0,
    allow: ["/home/user/**"],
    deny: ["**/.env", "**/.ssh/**"],
    operations: ["read", "write", "git.status", "git.commit", "shell.exec"],
    approve: ["shell.exec"],
    safety: "standard",
    taintedWritePolicy: "approve",
    toolRules: [
      { tool: "shell_*", policy: "approve" },
      { tool: "git_push", policy: "approve" },
    ],
    defaultToolPolicy: "allow",
    domainRules: [],
    compliance: ["SOC2-CC6.1"],
    credentials: ["github.pat"],
    canDelegate: true,
    trustedPaths: ["/home/user/Code/**"],
  },
  readonly: {
    ring: 2,
    allow: ["/home/user/projects/public/**"],
    deny: ["**/.env", "**/.ssh/**", "**/secrets/**"],
    operations: ["read", "search", "list"],
    approve: [],
    safety: "guardian",
    taintedWritePolicy: "deny",
    toolRules: [
      { tool: "file_write", policy: "deny" },
      { tool: "git_commit", policy: "deny" },
    ],
    defaultToolPolicy: "allow",
    domainRules: [
      { domain: "filesystem", operations: ["read"] },
      { domain: "shell", operations: [] },
    ],
    compliance: [],
    credentials: [],
    canDelegate: false,
    trustedPaths: [],
  },
};

export function PermissionsPanel() {
  const [config, setConfig] = useState<PermissionConfig>(MOCK_CONFIG);

  return <PermissionEditor config={config} onChange={setConfig} />;
}
