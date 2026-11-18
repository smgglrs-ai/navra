# Agent Rules

All AI agents working in this project must follow these rules.
These apply to all agents: main session, subagents, worktree
agents, and team members.

## 0. Build Machine Rules (ABSOLUTE — no exceptions)

Building and testing this workspace is HEAVY: full builds take
gigabytes of RAM per rustc/linker process, and the navra-server
test binaries each spawn real server processes. The primary
development machine is the user's daily-driver workstation —
running heavy jobs there disrupts the user's desktop and is
treated as a critical process failure.

1. **No heavy builds on the user's workstation.** `cargo build`,
   `cargo test`, `cargo clippy`, and `cargo check` must NEVER run
   on the machine you develop on. The only permitted cargo
   commands there are `cargo fmt` / `cargo fmt --check`. Run all
   compilation and tests on the designated build machine (ask the
   lead/operator which host that is — it is reached over SSH and
   configured as a git remote). Workflow: push your branch to that
   remote, clone or check out into your OWN directory there (one
   per agent, never shared), and iterate fix → commit → push →
   re-test over SSH. Never edit files on the build machine
   directly; git is the only transport.
2. **Check resources before and during.** Before starting work on
   the build machine, check `free -g`, `df -h`, current load
   (`uptime`), and that no stray processes from earlier runs are
   alive (`pgrep -f 'target/debug/navra'` — kill any you find,
   report them). If memory or disk are tight, or load is already
   high, stop and coordinate instead of piling on. While your jobs
   run, they must stay within the resource envelope below.
3. **navra-server tests are serialized, EVERYWHERE.** Plain
   `cargo test -p navra-server` runs every integration binary in
   parallel and each spawns multiple navra server processes —
   dozens of navra instances at once, on any machine. This is why
   `just test-crate navra-server` is blocked. The rule applies on
   every machine, including the build machine:
   - Use `just test-server-guarded` (serialized + a watchdog that
     aborts if more than 10 navra processes are alive at once) —
     preferred, or plain `just test-server`, or
   - Run ONE filtered test at a time:
     `cargo test -p navra-server --test <binary> <name> -- --test-threads=1`
   `cargo test -p <other-crate>` may run in parallel on the build
   machine, but never more than one cargo invocation at a time per
   agent. Never run two test-server invocations concurrently.
4. **Clean up after yourself**: kill any navra test processes you
   started (`pkill -f 'target/debug/navra'`), tell the lead which
   directory you used on the build machine, and leave no stray
   processes behind.

## 1. Path Precision

When referencing files, use exact paths relative to the project root.

- `navra-auth/src/permissions/acl.rs:42` — correct
- `navra-core/tests/session_test.rs` — correct
- "the security file" — wrong
- "acl.rs" — wrong (which crate?)

## 2. Context Protocol

### Session start

1. Read `CLAUDE.md` for architecture, conventions, and build commands
2. Read `.lean/plan.yml` to understand what's in progress (generated
   from `.lean/items/*.yml`, the source of truth — regenerate with
   `bash ~/.claude/lean/scripts/generate-plan.sh`)
3. Run `git log --oneline -10` for recent context
4. If assigned a crate, read its `lib.rs` top-level doc comment

### During work

- Do not re-read files you already have in context
- If you need a fact about the codebase, grep or read — do not guess
- When switching crates, read the new crate's `lib.rs` and test files

## 3. Work Quality Gates

Before claiming any work is complete:

1. **Tests pass**: run on the designated build machine per rule 0 —
   `cargo test -p <crate>` for non-server crates, `just
   test-server-guarded` (or one filtered test at a time) for
   navra-server
2. **Clippy clean**: `cargo clippy -p <crate> -- -D warnings` on the
   designated build machine
3. **No new warnings**: read the full build output, not just the exit code
4. **Security warnings are fatal**: if clippy or your own review flags
   a security concern, fix it or escalate — never defer

If tests fail, fix them. Do not report partial success as complete.

## 4. Git Discipline

- Sign all commits: `git commit -s -m "description"`
- One feature = one commit. Commit immediately after tests pass.
- Never commit: `.env`, `*.pem`, `*.key`, `Cargo.lock` changes
  (let the build update it), model weights, database files
- Never force push, rewrite history, or run destructive git commands
- Write commit messages in imperative mood: "add X", not "added X"

## 5. Worktree Protocol

### When to use worktrees

- Parallel work on independent crates (e.g., tests + docs)
- Multi-agent team assignments
- Experimental changes that might not land

### How worktrees work

1. **Plan on main**: design the approach, decompose into crate-scoped
   work packages, identify file ownership boundaries
2. **Implement in worktree**: each agent gets its own worktree on
   its own branch, modifying only its assigned crates
3. **Commit before exiting**: `git add -A && git commit -s -m "summary"`
   — uncommitted work is lost when the worktree is cleaned up
4. **Merge back**: `git merge --no-ff <worktree-branch> -m "Merge: description"`

### File ownership

Crate boundaries are the natural ownership boundary. When multiple
agents work in parallel:

- Each agent owns one or more crates (all files under that crate dir)
- Shared files (`Cargo.toml` workspace, `CLAUDE.md`, `AGENTS.md`)
  are owned by the lead session — agents do not modify them
- If two agents need to change the same file, they cannot run in
  parallel — sequence them or have one agent do both changes

### Agent checklist

Every agent in a worktree must:

- [ ] Read `CLAUDE.md` and `AGENTS.md` at session start
- [ ] Read the target crate's `lib.rs` and existing tests
- [ ] Run tests before and after changes
- [ ] Commit all work before finishing
- [ ] Report what was done, what was not, and why

## 6. Team Coordination

When working as part of a Claude Code team:

- **Lead** decomposes the task, assigns crates, creates the task list
- **Members** claim tasks, work in worktrees, report via SendMessage
- **No silent work**: if you hit a blocker, message the lead immediately
- **No scope creep**: do your assigned task, nothing more
- Prefer tasks in ID order (lowest first) when multiple are available

## 7. Crate Conventions

Before modifying a crate, understand its patterns:

- Check for a local `test_ctx()` helper — use it, don't invent your own
- Check the error handling pattern: `CallToolResult::error()` vs `anyhow`
- Check whether the crate uses `#[tokio::test]` or sync tests
- Match the existing naming: `test_deny_wins_over_allow`, not `test1`
- Respect the dependency layering in `CLAUDE.md` — never add a
  dependency that violates the crate hierarchy
