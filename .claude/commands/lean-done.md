# Completion Gate

Mark the current in-progress item as done after passing all checks.
This replaces the Python classifier, drift detector, and reviewer.

## Steps

### 1. Identify the item

Read `.lean/plan.yml` and find the item with `status: in_progress`.
If multiple, ask which one to complete.

### 2. Autonomy check

Read `.lean/project.yml` `autonomy` section. Run `git diff --name-only`
to see what files changed. Classify the change:

- If changes touch only files in **autonomous** scope (tests, docs,
  linting, refactoring) and all tests pass: proceed.
- If changes touch **notify** scope (internal APIs, config): proceed
  but include a detailed summary in the activity log.
- If changes touch **approve** scope (public API, features, schema,
  architecture): **STOP**. Tell the human this needs approval before
  marking done. Set status to `pending_approval` instead.
- If changes touch **discuss** scope (core protocol, security,
  breaking changes): **STOP**. Open a discussion with the human.

### 3. Full verification

Determine the verification command:
- The item's own `verification.full` if present
- The project's `verification.full` from `.lean/project.yml`
- Fall back to `poetry run pytest && poetry run ruff check src/ tests/`

Run it. If it fails, report the failures and stop. Do not mark done.

### 4. Acceptance check (drift detection)

If the item has `acceptance` criteria, walk each one:
- For each criterion, check if the implementation meets it
- Report each as **MET** or **NOT MET** with brief evidence
- If any are NOT MET, stop and report what's missing

If the item has no acceptance criteria, skip this step.

### 5. Self-review

Perform a quick quality check:
- **Scope**: does the diff contain changes unrelated to this item?
  Flag any scope creep.
- **Quality**: are there obvious issues (missing error handling at
  boundaries, hardcoded values that should be configurable, missing
  type hints on public functions)?
- **ADR**: did this work involve a significant architectural decision
  that should be recorded? If so, flag it.

### 6. Complete

If all checks pass:
1. Update the item's `status` to `done` and `progress` to `100`
   in `.lean/plan.yml`
2. Append an activity log entry to `.lean/activity.log` with:
   - What was completed
   - Key artifacts (files created/modified)
   - Any decisions made (with ADR refs if applicable)
