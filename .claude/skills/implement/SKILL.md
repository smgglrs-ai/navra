---
name: implement
description: Orchestrate plan-then-implement workflow for a roadmap item using worktree-isolated agents
---

Implement a roadmap item by decomposing it into crate-scoped work
packages and optionally parallelizing with worktree-isolated agents.

## Usage

The user provides a roadmap item ID (e.g., `TW7`, `U3`, `9aa`) or
a free-form task description.

## Workflow

### 1. Understand the item

If a roadmap ID is given:
- Read `roadmap.json` to get the item's title, dependencies, gates
- Verify all dependencies are completed
- If gated, check whether the gate has cleared

If a free-form task:
- Understand the scope from the user's description

### 2. Plan the implementation

Stay on the main branch. Do not create worktrees yet.

- Identify which crates need changes
- Read each target crate's `lib.rs` and existing patterns
- Design the approach: what types, traits, functions to add/modify
- Identify file ownership boundaries for parallel work
- Present the plan to the user for approval

### 3. Decompose into work packages

For each crate that needs changes, create a work package:
- What files to modify
- What tests to add
- Dependencies on other work packages (if any)

### 4. Implement

**Single crate**: work directly on main, no worktree needed.

**Multiple independent crates**: spawn agents with
`isolation: worktree`, one per crate. Each agent:
- Gets the plan and its specific work package
- Implements, tests, and commits in its worktree
- Reports back on completion

**Sequential dependencies**: implement in order, one at a time.

### 5. Merge and verify

After all agents complete:
1. Merge each worktree branch: `git merge --no-ff <branch> -m "Merge: description"`
2. Run full workspace tests: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace`
3. Run clippy: `ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo clippy --workspace -- -D warnings`

### 6. Update roadmap

Set the item's status to `completed` in `roadmap.json`.
Commit the roadmap change with the feature.

## Notes

- Always read AGENTS.md rules before spawning agents
- Keep teams to 3-5 agents maximum
- If a worktree agent fails, debug in the worktree before merging
- Never merge a worktree with failing tests
