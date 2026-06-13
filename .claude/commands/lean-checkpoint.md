# Session Checkpoint

Save session state for fast resume. Target: under 2 minutes.

## Steps

### 1. Capture git state

Run `git status --short` and `git diff --stat`. Note the current branch.

### 2. Capture plan state

Read `.lean/plan.yml`. Find items with `status: in_progress` — note their
id, title, and progress percentage.

### 3. Write checkpoint

Write `.lean/session_state.md` with this exact structure. No preamble,
no commentary, no extra sections:

```markdown
---
timestamp: <ISO 8601>
branch: <current git branch>
uncommitted_files: <count from git status>
---

## In Progress
- <plan item title> (id: N, progress: X%)

## Accomplished This Session
- <one bullet per completed or meaningfully advanced item>

## Next
- <one bullet per logical next step>

## Decisions
- <any decisions made this session not yet captured in .lean/decisions/>
```

If a section has no items, write `- (none)` under it.

### 4. Commit WIP if needed

If there are uncommitted changes:
1. `git add -A`
2. `git commit -s -m "wip: checkpoint — <brief description of in-progress work>"`

If there are no uncommitted changes, skip this step.

### 5. Update activity log

Append one entry to `.lean/activity.log`:

```yaml
- timestamp: "<ISO 8601>"
  actor: claude
  action: checkpoint
  summary: "<one-line summary of session state>"
```

### 6. Done

Print: `Checkpoint saved. Resume with /lean-start.`

No summary, no questions, no follow-up suggestions.
