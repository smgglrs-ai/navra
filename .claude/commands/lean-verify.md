# Quick Verification Loop

Run a quick verification pass for the current work.

## Steps

1. **Find the in-progress item**: Read `.lean/plan.yml` and find the
   item with `status: in_progress`. If multiple, pick the one most
   recently worked on (highest ID or most recent activity).

2. **Determine verification command**: Use this priority:
   - The item's own `verification.quick` if present
   - The project's `verification.quick` from `.lean/project.yml`
   - Fall back to `poetry run pytest tests/ -x -q`

3. **Run the command**: Execute it and capture output.

4. **Report results**:
   - **Pass**: report success briefly, note which tests ran
   - **Fail**: show the failing test name, the assertion or error
     message, and the relevant file:line. If the fix is obvious,
     suggest it. Do not auto-fix unless asked.
