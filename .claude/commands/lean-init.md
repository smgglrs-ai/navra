# Initialize lean-claude for this project

Bootstrap `.lean/` project intelligence and `.claude/` settings by reading
existing project artifacts. You reconstruct context — the user corrects
rather than authors.

Run all 4 phases sequentially. Do not skip phases.

## Phase 1: Detect

Read the project to determine stack, conventions, and current state.
Do not write any files in this phase.

### 1a. Stack detection

Check which build files exist and read them:

| File | Stack | Read for |
|------|-------|----------|
| `Cargo.toml` | Rust | workspace members, edition, test/bench targets, features |
| `go.mod` | Go | module path, Go version, key dependencies |
| `Makefile` or `meson.build` | C/C++ | build targets, test targets, compiler flags |
| `package.json` | JS/TS | scripts (test, build, lint), dependencies |
| `pyproject.toml` | Python | build system, test/lint tools, dependencies |
| `pubspec.yaml` | Flutter/Dart | dependencies, dev_dependencies |

If multiple exist (e.g., `Makefile` + `Cargo.toml`), the more specific
one wins (Cargo.toml = Rust, not C).

Extract: language, test command, build command, lint command, formatter.

### 1b. Git analysis

Run these commands:
```bash
git log --oneline -20
git log --format='%s' -50 | grep -c 'Signed-off-by' # signoff convention
git remote -v
git branch --show-current
git status --short
```

Extract: repo URL, commit message style, whether signoff is used,
current branch, uncommitted file count.

### 1c. Existing configuration

Read if they exist (silently skip if missing):
- `CLAUDE.md` — extract build/test instructions, conventions, architecture
- `.claude/settings.json` — note existing permissions and hooks
- `README.md` — first 2 paragraphs for project description
- `LICENSE` — note license type, flag GPL if present

Also read existing memory files:
```bash
encoded=$(pwd | tr '/' '-' | sed 's/^-//')
sessions_dir="$HOME/.claude/projects/-$encoded"
```
Read `$sessions_dir/memory/MEMORY.md` and all linked files if they exist.

### 1d. Code style detection

Check which style config files exist:
- `.rustfmt.toml` or `rustfmt.toml` → auto-rustfmt hook
- `.clang-format` → auto-clang-format hook
- `ruff.toml` or `pyproject.toml` with `[tool.ruff]` → auto-ruff hook
- `.editorconfig` → note settings
- `.eslintrc*` or `eslint.config.*` → note

### 1e. CI detection

Check which CI files exist:
- `.github/workflows/*.yml` — read for test/build steps
- `.gitlab-ci.yml` — read for test/build stages

Compare detected test commands against CI to validate.

### 1f. Present detection summary

Print a concise summary of what was detected:
```
Stack: Rust (cargo workspace, 22 crates)
Build: cargo build (with ORT_LIB_PATH)
Test:  cargo test --workspace
Lint:  cargo clippy
Format: rustfmt (config detected)
Git: signoff required, remote: github.com/smgglrs-ai/navra
License: Apache-2.0
CI: GitHub Actions (test + clippy)
CLAUDE.md: exists (363 lines)
.claude/settings.json: exists (60 permissions, 2 hooks)
Memory: 45 files
Sessions: 261 JSONL files
WIP: 3 uncommitted files on branch feature/xyz
```

## Phase 2: Learn (optional — runs if sessions exist)

Check if session JSONL files exist for this project:
```bash
session_count=$(ls "$sessions_dir"/*.jsonl 2>/dev/null | wc -l)
```

If `session_count > 0`, ask the user:
> "Found N past sessions. Run learning cycle to extract corrections,
> decisions, and references from session history? [y/N]"

If the user says yes, invoke `/lean-learn --extract`. This calls the
Workflow tool to fan out agents across the session files, extracting
unrecorded knowledge and classifying each finding by destination
(CLAUDE.md, .lean/decisions/, memory/).

Collect the accepted findings — they feed into Phase 3.

If the user says no, or if no sessions exist, skip to Phase 3
with an empty findings set.

## Phase 3: Generate

Build all files as temporary drafts. Combine Phase 1 detection with
Phase 2 learning results. Write everything to disk so the user can
review actual files, not descriptions.

### 3a. `.lean/project.yml`

Generate from Phase 1 detection:
- `name`: from git remote basename or directory name
- `version`: "0.1.0" (default)
- `description`: from README.md first paragraph or CLAUDE.md first section
- `repository`: from git remote URL
- `type`: "single-repo" (default) or "monorepo" if workspace detected
- `stack`: populated from detection (language, build tools, test framework)
- `autonomy`: use the standard 4-tier defaults
- `verification.quick`: the detected quick test command
- `verification.full`: the detected full test + lint command

### 3b. `.lean/plan.yml`

```yaml
version: 1
items: []
```

If `gh issue list` or `glab issue list` is available and returns results,
ask the user whether to seed plan items from open issues.

### 3c. `.lean/activity.log`

Seed from last 5 git commits:
```yaml
- timestamp: "<commit date ISO8601>"
  actor: "<commit author name>"
  action: commit
  summary: "<commit message first line>"
```

### 3d. `.lean/session_state.md`

Only if `git status --short` showed uncommitted changes.

### 3e. `.lean/decisions/`

Write ADRs from Phase 2 learning findings that were classified as
`lean_decisions`. Use `0001-<slug>.md` format with
Status/Date/Context/Decision/Consequences.

### 3f. `.claude/settings.json`

Generate stack-appropriate permissions. If a `.claude/settings.json`
already exists, present a diff of what would be added — do not
overwrite existing permissions or hooks.

**Permission templates by stack:**

Rust:
```
cargo build/test/check/clippy/fmt/run/doc/tree/metadata/bench/expand/search,
rustfmt, rustup, ORT_LIB_PATH variants, just
```

Go:
```
go build/test/vet/mod/generate/doc/install, golangci-lint, protoc,
dlv (debugger), mockgen
```

C:
```
make, meson, ninja, cmake, clang/gcc, clang-format, clang-tidy,
cppcheck, cbmc, frama-c, tlc, valgrind, pkg-config
```

Python:
```
pytest, ruff, mypy, poetry/pip, python3, black, isort
```

TypeScript:
```
npm run/install/test/build, npx, tsc, eslint, prettier
```

Flutter:
```
flutter test/build/run/analyze/pub, dart analyze/format/test
```

All stacks get common read-only commands (already in global settings)
plus git write commands: `git add`, `git commit`, `git merge`, `git worktree`.

Plus deny rules:
```
git push --force, git reset --hard, rm -rf /, sudo
```

Plus hooks:
- **PreToolUse (Write|Edit|MultiEdit)**: Plan gate — blocks source
  code writes when no plan item is `in_progress`. Only activates if
  `.lean/plan.yml` exists; config/doc/markdown files are always allowed.
- **PreToolUse (Write|Edit)**: Block writes to lock files
  (`Cargo.lock`, `go.sum`, `package-lock.json`, `poetry.lock`),
  secrets (`.env`, `.pem`, `.key`, `credentials`)
- **PostToolUse (Write|Edit)**: Auto-format if style config detected

### 3g. `.claude/commands/`

Copy lean-claude commands into the project:
`lean-start.md`, `lean-next.md`, `lean-verify.md`,
`lean-checkpoint.md`, `lean-learn.md`, `lean-done.md`.

Read the source files from `~/.claude/commands/lean-*.md`.

### 3h. `CLAUDE.md`

If no CLAUDE.md exists: generate a minimal one with project context,
build/test commands, workflow skills section, and any rules from
Phase 2 learning findings classified as `claude_md`.

If CLAUDE.md already exists: append learned rules to the appropriate
sections. Show the diff.

### 3i. Memory files

Write any Phase 2 learning findings classified as `memory_*` to
`$sessions_dir/memory/` with proper frontmatter. Update MEMORY.md index.

## Phase 4: Confirm

All files from Phase 3 are now on disk as drafts. Present a summary
and let the user review the actual files:

```
Files generated:
  .lean/project.yml     — Rust project, cargo test --workspace
  .lean/plan.yml        — empty (or N items from issues)
  .lean/activity.log    — 5 entries from git history
  .lean/decisions/      — M ADRs from learning cycle
  .claude/settings.json — 45 permissions, 2 hooks
  .claude/commands/     — 7 lean-* commands
  CLAUDE.md             — 3 rules added from learning cycle
  memory/               — K files from learning cycle

Review any file before confirming. Reject to discard all changes.
Keep? [Y/n]
```

If the user rejects, remove all generated files. If they want to
edit specific files first, let them — then re-confirm.

After confirmation: `Done. Run /lean-start to begin.`
