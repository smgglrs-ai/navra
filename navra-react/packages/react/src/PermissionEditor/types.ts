export interface ToolRule {
  tool: string;
  policy: "allow" | "deny" | "approve";
}

export interface DomainRule {
  domain: string;
  operations: string[];
}

export interface PermissionSet {
  ring?: number;
  allow: string[];
  deny: string[];
  operations: string[];
  approve: string[];
  safety: string;
  taintedWritePolicy: string;
  toolRules: ToolRule[];
  defaultToolPolicy: string;
  domainRules: DomainRule[];
  compliance: string[];
  credentials: string[];
  canDelegate: boolean;
  rateLimit?: string;
  trustedPaths: string[];
}

export interface PermissionConfig {
  [name: string]: PermissionSet;
}

export function defaultPermissionSet(): PermissionSet {
  return {
    allow: [],
    deny: [],
    operations: [],
    approve: [],
    safety: "standard",
    taintedWritePolicy: "allow",
    toolRules: [],
    defaultToolPolicy: "allow",
    domainRules: [],
    compliance: [],
    credentials: [],
    canDelegate: false,
    trustedPaths: [],
  };
}

export function permissionSetToToml(name: string, ps: PermissionSet): string {
  const lines: string[] = [`[permissions.${name}]`];

  if (ps.ring !== undefined) lines.push(`ring = ${ps.ring}`);
  if (ps.allow.length > 0)
    lines.push(`allow = [${ps.allow.map((s) => `"${s}"`).join(", ")}]`);
  if (ps.deny.length > 0)
    lines.push(`deny = [${ps.deny.map((s) => `"${s}"`).join(", ")}]`);
  if (ps.operations.length > 0)
    lines.push(
      `operations = [${ps.operations.map((s) => `"${s}"`).join(", ")}]`,
    );
  if (ps.approve.length > 0)
    lines.push(`approve = [${ps.approve.map((s) => `"${s}"`).join(", ")}]`);

  lines.push(`safety = "${ps.safety}"`);
  lines.push(`tainted_write_policy = "${ps.taintedWritePolicy}"`);
  lines.push(`default_tool_policy = "${ps.defaultToolPolicy}"`);

  if (ps.canDelegate) lines.push(`can_delegate = true`);
  if (ps.rateLimit) lines.push(`rate_limit = "${ps.rateLimit}"`);
  if (ps.compliance.length > 0)
    lines.push(
      `compliance = [${ps.compliance.map((s) => `"${s}"`).join(", ")}]`,
    );
  if (ps.credentials.length > 0)
    lines.push(
      `credentials = [${ps.credentials.map((s) => `"${s}"`).join(", ")}]`,
    );
  if (ps.trustedPaths.length > 0)
    lines.push(
      `trusted_paths = [${ps.trustedPaths.map((s) => `"${s}"`).join(", ")}]`,
    );

  for (const rule of ps.toolRules) {
    lines.push("");
    lines.push(`[[permissions.${name}.tool_rules]]`);
    lines.push(`tool = "${rule.tool}"`);
    lines.push(`policy = "${rule.policy}"`);
  }

  for (const rule of ps.domainRules) {
    lines.push("");
    lines.push(`[[permissions.${name}.domain_rules]]`);
    lines.push(`domain = "${rule.domain}"`);
    lines.push(
      `operations = [${rule.operations.map((s) => `"${s}"`).join(", ")}]`,
    );
  }

  return lines.join("\n");
}

export interface ValidationWarning {
  field: string;
  message: string;
}

export function validatePermissionSet(ps: PermissionSet): ValidationWarning[] {
  const warnings: ValidationWarning[] = [];

  for (const denied of ps.deny) {
    for (const allowed of ps.allow) {
      if (denied === allowed) {
        warnings.push({
          field: "deny",
          message: `"${denied}" appears in both allow and deny — deny wins`,
        });
      }
    }
  }

  for (const op of ps.approve) {
    if (!ps.operations.includes(op)) {
      warnings.push({
        field: "approve",
        message: `"${op}" requires approval but is not in operations list`,
      });
    }
  }

  if (ps.ring !== undefined && (ps.ring < 0 || ps.ring > 3)) {
    warnings.push({
      field: "ring",
      message: `Ring must be 0-3, got ${ps.ring}`,
    });
  }

  return warnings;
}
