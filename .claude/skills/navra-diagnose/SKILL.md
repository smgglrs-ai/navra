---
name: navra-diagnose
description: Explain why a navra tool call was blocked — reads audit trail, traces denial chain, suggests fix
---

Diagnose navra security denials by reading the blackbox audit log.

## Usage

- `/navra-diagnose` — show recent denials and explain each
- `/navra-diagnose file_write` — filter by tool name
- `/navra-diagnose claude` — filter by agent name
- User can also describe the problem: "my git push was blocked"

## Workflow

### 1. Locate the blackbox database

```bash
DB="${XDG_DATA_HOME:-$HOME/.local/share}/navra/blackbox.db"
```

If it doesn't exist, tell the user navra hasn't recorded any
activity yet (is the service running?).

### 2. Query recent denials

```bash
sqlite3 "$DB" "
  SELECT seq, datetime(timestamp_ms/1000, 'unixepoch', 'localtime') as time,
         agent_name, tool_name, outcome, ifc_label
  FROM blackbox
  WHERE outcome LIKE 'denied_%'
  ORDER BY seq DESC
  LIMIT 20;
"
```

If the user specified a tool name, add `AND tool_name LIKE '%<tool>%'`.
If the user specified an agent, add `AND agent_name LIKE '%<agent>%'`.

To get full details on a specific denial:

```bash
sqlite3 "$DB" "
  SELECT seq, datetime(timestamp_ms/1000, 'unixepoch', 'localtime') as time,
         agent_name, agent_perms, tool_name, tool_args, outcome, ifc_label
  FROM blackbox
  WHERE seq = <seq>;
"
```

### 3. Explain each denial type

**`denied_acl`** — Path or tool rule blocked the call.

Read the navra config to find the matching rule:

```bash
cat ~/.config/navra/config.toml
```

Look at the agent's permission set (from `agent_perms` field).
Check:
- Is the target path covered by an `allow` pattern?
- Does a `deny` pattern match it?
- Is the operation in the `operations` list?
- Does a `tool_rules` entry block this tool?
- Is `default_tool_policy = "deny"`?

Report: "Tool `{tool}` was blocked because deny rule `{pattern}`
matched the target path" or "Operation `{op}` is not in the
permission set's `operations` list."

**`denied_ifc`** — Information Flow Control violation.

The session was tainted by a prior read, and the write was blocked.
Find the taint source:

```bash
sqlite3 "$DB" "
  SELECT seq, tool_name, ifc_label
  FROM blackbox
  WHERE session_id = (
    SELECT session_id FROM blackbox WHERE seq = <denied_seq>
  )
  AND seq < <denied_seq>
  AND ifc_label != 'Trusted:Public'
  ORDER BY seq;
"
```

Report: "The session was tainted at step {seq} when `{tool}`
returned data labeled `{label}`. The subsequent write to `{tool}`
was blocked because the tainted session cannot write to a less
sensitive target (Bell-LaPadula no-write-down property)."

**`denied_rate`** — Rate limit exceeded.

Report: "Agent `{agent}` exceeded the rate limit for permission
set `{perms}`. Check the `rate_limit` field in the config."

### 4. Suggest minimal fix

For each denial, suggest the smallest config change that would
allow it — but warn about security implications.

**ACL denial fixes:**

- Missing allow: "Add `{path}` to the `allow` list in
  `[permissions.{set}]`"
- Deny rule match: "The deny rule `{pattern}` blocks this path.
  If this is intentional, no change needed. To allow it, remove
  the deny rule — but this may expose sensitive files."
- Missing operation: "Add `{op}` to the `operations` list"
- Tool rule: "Change the tool rule for `{tool}` from `deny` to
  `allow` (or `approve` for human-in-the-loop)"

**IFC denial fixes:**

- "This is by design — navra prevents data exfiltration by
  blocking writes after reading sensitive data. Options:
  1. Use separate sessions for reading and writing
  2. Set `tainted_write_policy = \"approve\"` to allow with
     human approval
  3. Add the source path to `trusted_paths` if the data is
     not actually sensitive"

**Rate limit fixes:**

- "Increase the rate limit: `rate_limit = \"120/60\"` (120
  calls per 60 seconds)"

### 5. Security warnings

Always warn when a suggestion would weaken security:

- Adding `.env` or `*secret*` paths to allow → "This would
  expose credential files. Consider using environment variables
  or a credential manager instead."
- Removing deny rules → "Deny rules are your last line of defense.
  Only remove them if you're certain the path is safe."
- Setting `tainted_write_policy = "allow"` → "This disables
  exfiltration prevention. Use `approve` instead to keep human
  oversight."
- Changing `safety = "none"` → "This disables all content
  filtering including secret detection."

## Notes

- The blackbox is append-only with SHA-256 hash chains — entries
  cannot be tampered with
- If the database has many entries, always use LIMIT to avoid
  dumping thousands of rows
- The `tool_args` field may be truncated to 4096 bytes and
  PII-filtered — partial information is expected
- If no denials are found, check if navra is running:
  `systemctl --user status navra`
