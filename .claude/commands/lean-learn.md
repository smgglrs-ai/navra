# Learn from Session History

Analyze past sessions and current context to extract, compress, decay,
and rebalance project knowledge. Each run makes the next session sharper.

Use `$ARGUMENTS` to control scope:
- No args: full learning cycle (extract + compress + decay + rebalance)
- `--extract`: only extract new knowledge from recent sessions
- `--compress`: only merge redundant/related entries
- `--decay`: only flag stale/obsolete entries
- `--rebalance`: only audit knowledge placement (CLAUDE.md vs memory vs .lean/)
- `--dry-run`: show findings without writing anything

## Step 1: Gather inputs

Before launching the workflow, collect the data it needs.

### 1a. Compute sessions directory

```bash
encoded=$(pwd | tr '/' '-' | sed 's/^-//')
sessions_dir="$HOME/.claude/projects/-$encoded"
ls "$sessions_dir"/*.jsonl 2>/dev/null | wc -l
```

### 1b. List session files

```bash
ls "$sessions_dir"/*.jsonl 2>/dev/null | xargs -n1 basename
```

### 1c. Read all existing knowledge

Read and concatenate into a single text block:
- `CLAUDE.md` (full content)
- All files in `$sessions_dir/memory/` (each with filename header)
- `.lean/project.yml`, `.lean/plan.yml` (if they exist)
- All files in `.lean/decisions/` (if they exist)

### 1d. Determine which phases to run

Parse `$ARGUMENTS`:
- `--extract` → `phases: ["extract"]`
- `--compress` → `phases: ["compress"]`
- `--decay` → `phases: ["decay"]`
- `--rebalance` → `phases: ["rebalance"]`
- No args → `phases: ["extract", "compress", "decay", "rebalance"]`

## Step 2: Launch the workflow

Call the **Workflow tool** with the script below. This is mandatory —
do NOT attempt to run the analysis inline or spawn agents manually.

Pass `args` as a JSON object:
- `sessionsDir` (string): the sessions directory path
- `sessionFiles` (array of strings): JSONL filenames from 1b
- `existingKnowledge` (string): the concatenated text from 1c
- `projectDir` (string): the current working directory (for code verification in decay)
- `phases` (array of strings): which phases to run from 1d

```javascript
export const meta = {
  name: 'lean-learn',
  description: 'Self-learning cycle: extract, compress, decay, rebalance project knowledge',
  phases: [
    { title: 'Extract', detail: 'Mine sessions for corrections and decisions' },
    { title: 'Compress', detail: 'Find redundant and mergeable knowledge' },
    { title: 'Decay', detail: 'Flag stale or superseded entries' },
    { title: 'Rebalance', detail: 'Audit knowledge placement across layers' }
  ]
}

const SESSIONS_DIR = args.sessionsDir
const SESSION_FILES = args.sessionFiles
const EXISTING = args.existingKnowledge
const PROJECT_DIR = args.projectDir
const PHASES = args.phases || ['extract', 'compress', 'decay', 'rebalance']

const FINDING_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          phase: { type: 'string', enum: ['extract', 'compress', 'decay', 'rebalance'] },
          action: { type: 'string', enum: ['add', 'merge', 'remove', 'move', 'archive'] },
          destination: { type: 'string', enum: ['claude_md', 'lean_decisions', 'memory_feedback', 'memory_project', 'memory_reference', 'lean_plan', 'lean_archive'] },
          source: { type: 'string', description: 'Where the finding came from (session file, memory file, etc.)' },
          title: { type: 'string', description: 'Short title for the finding' },
          content: { type: 'string', description: 'The rule, decision, or merged text' },
          reason: { type: 'string', description: 'Why this action is recommended' }
        },
        required: ['phase', 'action', 'destination', 'title', 'content', 'reason']
      }
    }
  },
  required: ['findings']
}

const allFindings = []

// ─── EXTRACT ───────────────────────────────────────────────
if (PHASES.includes('extract') && SESSION_FILES.length > 0) {
  phase('Extract')
  log(`Scanning ${SESSION_FILES.length} sessions for corrections and decisions`)

  const extractResults = await pipeline(
    SESSION_FILES,
    (sessionFile) => agent(
      `Read the session JSONL file at ${SESSIONS_DIR}/${sessionFile}.

Read lines with "type":"user" to find the user's messages.
Skip assistant, system, attachment, and tool-result lines.

Extract two kinds of findings:

1. CORRECTIONS — the user telling Claude to stop, change, or redo:
   - Frustration: capitalized words, profanity, "READ", "STOP", "DON'T"
   - Redirects: "no, not that", "I said X not Y", "that's wrong"
   - Rules: "always do X", "never do Y", "use Z instead"
   - Workflow: "commit first", "test before", "don't skip"

2. DECISIONS — the user choosing an approach with rationale:
   - "Let's use X because Y"
   - "We decided / I chose / the trade-off is"
   - Technology selections, architecture choices, naming decisions

Check each finding against this existing knowledge — SKIP if already captured:
${EXISTING}

Classify destination:
- claude_md: build/test/commit/workflow rules (must follow every session)
- lean_decisions: architectural choices with rationale (ADR-worthy)
- memory_feedback: project-specific "don't do X" corrections
- memory_project: project context, state, landscape analysis
- memory_reference: external URLs, papers, tools, Jira references
- lean_plan: active work items discovered

Set phase to "extract" and action to "add" for all findings.
Set source to "${sessionFile}".
Return ONLY new findings. Empty array if nothing new.`,
      {
        label: 'extract:' + sessionFile.slice(0, 8),
        phase: 'Extract',
        schema: FINDING_SCHEMA
      }
    )
  )

  const extracted = extractResults.filter(Boolean).flatMap(r => r.findings)
  const seen = new Set()
  for (const f of extracted) {
    const key = f.title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
    if (!seen.has(key)) {
      seen.add(key)
      allFindings.push(f)
    }
  }
  log(`Extract: ${allFindings.length} unique findings from ${extracted.length} raw`)
}

// ─── COMPRESS ──────────────────────────────────────────────
if (PHASES.includes('compress')) {
  phase('Compress')
  log('Analyzing knowledge base for redundancy')

  const compressResult = await agent(
    `You are auditing a project's knowledge base for redundancy.

Here is ALL the project knowledge:
${EXISTING}

Find:
1. DUPLICATE RULES: two entries saying the same thing differently.
   Propose which to keep, which to remove.
2. MERGEABLE RULES: related entries to consolidate (e.g., multiple
   git rules → one "Git conventions" section).
3. REDUNDANT WITH CODE: rules restating what project.yml or CLAUDE.md
   already specifies elsewhere.
4. SERIES TO SUMMARIZE: multiple dated entries on the same topic
   (e.g., tech_watch_2026_04_19, _04_20, ...) → distill into one
   summary, archive originals.
5. ACTIVITY LOG: if over 50 entries, propose keeping last 20,
   summarizing the rest.

Set phase to "compress".
Set action to "merge" for consolidations, "archive" for series summaries,
"remove" for pure duplicates.
Set source to the file(s) being affected.
Set content to the proposed merged/summarized text.`,
    { label: 'compress', phase: 'Compress', schema: FINDING_SCHEMA }
  )
  if (compressResult) allFindings.push(...compressResult.findings)
  log(`Compress: ${compressResult ? compressResult.findings.length : 0} opportunities found`)
}

// ─── DECAY ─────────────────────────────────────────────────
if (PHASES.includes('decay')) {
  phase('Decay')
  log('Checking knowledge base for staleness')

  const decayResult = await agent(
    `You are auditing a project's knowledge base for staleness.
The project is at: ${PROJECT_DIR}

Here is the knowledge base:
${EXISTING}

For EACH rule, memory, and decision entry, verify it is still current:

1. Does the described tool/command still exist? Run: which, ls, or
   grep -r to check the project files at ${PROJECT_DIR}.
2. Is the described behavior still possible? Check if the code or
   config the rule addresses still exists in the project.
3. Has a later decision superseded this one? Look for newer entries
   on the same topic.
4. Is "current work" actually current? Check git log at ${PROJECT_DIR}
   and any plan.yml for updated status.
5. Do referenced URLs still resolve? Spot-check with curl.

Set phase to "decay".
Set action to "remove" for stale entries, "archive" for superseded
decisions (ADRs are historical — archive, don't delete).
Set source to the file being flagged.
Set reason to WHY it's stale (what changed, what's missing).
Only flag entries you have EVIDENCE are stale — not just old.`,
    { label: 'decay', phase: 'Decay', schema: FINDING_SCHEMA }
  )
  if (decayResult) allFindings.push(...decayResult.findings)
  log(`Decay: ${decayResult ? decayResult.findings.length : 0} stale entries found`)
}

// ─── REBALANCE ─────────────────────────────────────────────
if (PHASES.includes('rebalance')) {
  phase('Rebalance')
  log('Auditing knowledge placement across layers')

  const rebalanceResult = await agent(
    `You are auditing where knowledge lives in a Claude Code project.

The layers and their loading behavior:
- CLAUDE.md: loaded EVERY session, always in context. For rules that
  must be followed unconditionally: build/test commands, commit
  conventions, workflow rules, "never/always" constraints.
- memory/: loaded ONLY when Claude Code deems it relevant. For
  reference material, landscape analysis, external pointers, user
  profile, project context that's useful but not mandatory.
- .lean/decisions/: versioned ADRs, read on demand. For architectural
  choices with rationale.
- .lean/project.yml: loaded by /lean-start. Stack config, autonomy
  policy, verification commands.

Here is what's in each layer:
${EXISTING}

Find:
1. PROMOTE TO CLAUDE.md: memory entries containing rules the agent
   should follow every session. These are misplaced — memory isn't
   reliably loaded.
2. DEMOTE FROM CLAUDE.md: sections that are reference material or
   architecture detail, not actionable rules. They waste the
   always-loaded context budget.
3. CONSOLIDATE IN .lean/: memory entries better structured as ADRs
   or project.yml fields.
4. CONTEXT BUDGET: flag CLAUDE.md if over 150 lines, memory/ if
   over 30 files, plan.yml if over 30 items.

Set phase to "rebalance", action to "move".
Set source to the current location, destination to the target layer.
Explain what breaks or degrades if it stays where it is.`,
    { label: 'rebalance', phase: 'Rebalance', schema: FINDING_SCHEMA }
  )
  if (rebalanceResult) allFindings.push(...rebalanceResult.findings)
  log(`Rebalance: ${rebalanceResult ? rebalanceResult.findings.length : 0} suggestions`)
}

// ─── RETURN ────────────────────────────────────────────────
log(`Learning complete: ${allFindings.length} total findings across ${PHASES.join(', ')}`)
return { findings: allFindings, phases: PHASES }
```

## Step 3: Present findings

After the workflow completes, group its returned `findings` by phase
and destination. Present to the user:

```
## Learning Results

### Extract (N findings)
  → CLAUDE.md: "rule text" — from session abc123
  → .lean/decisions/: "decision text" — from session def456
  → memory/: "reference text" — from session ghi789

### Compress (M findings)
  merge: feedback_agent_workflow.md + feedback_worktree_commits.md → 1 file
  archive: 11 tech_watch files → 1 summary

### Decay (K findings)
  stale: project_current_work.md — describes done items
  stale: reference_old_api.md — URL returns 404

### Rebalance (J findings)
  promote: feedback_use_venv.md → CLAUDE.md (per-session rule)
  demote: architecture section → .lean/architecture.md

Accept all? [Y/n] Or specify numbers to exclude.
```

If `--dry-run` was passed, show findings and stop. Do not write.

## Step 4: Apply accepted findings

For each accepted finding, write the changes:

1. **`add` to `claude_md`**: Append rule to the appropriate CLAUDE.md
   section. Show the exact edit before applying.

2. **`add` to `lean_decisions`**: Write `.lean/decisions/NNNN-slug.md`
   with Status/Date/Context/Decision/Consequences template.

3. **`add` to `memory_*`**: Write memory file with frontmatter
   (name, description, metadata.type). Update MEMORY.md index.

4. **`merge`**: Write the merged content to the target file, remove
   the source files. Update MEMORY.md index.

5. **`remove` / `archive`**: Move to `.lean/archive/`. Never delete.

6. **`move`**: Write to new location, remove from old location.
   Update MEMORY.md index and CLAUDE.md as needed.

7. **Activity log**: Append one entry:
   ```yaml
   - timestamp: "<ISO8601>"
     actor: claude
     action: learn
     summary: "Extracted N, compressed M, decayed K, rebalanced J"
   ```

Report: "Learning cycle complete. Context optimized for next session."
