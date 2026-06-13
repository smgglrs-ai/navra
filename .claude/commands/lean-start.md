# Session Start Protocol

You are beginning a development session. Follow these steps exactly:

## 1. Check for checkpoint

If `.lean/session_state.md` exists, read it first. This is a resume
from a previous `/lean-checkpoint`. Present the checkpoint summary
before loading the full plan state.

## 2. Load project state

Read these files in order:
1. `.lean/plan.yml` — current priorities and progress
2. `.lean/reports/status.md` — latest status briefing
3. `.lean/activity.log` (last 10 entries) — recent work

## 3. Present briefing

Summarize concisely:
- **Done**: items completed since last session
- **In progress**: items currently being worked on (with progress %)
- **Next up**: highest-priority planned items that are unblocked
- **Recent activity**: last 3-5 activity log entries (one line each)

## 4. Load autonomy policy

Read `.lean/project.yml` `autonomy` section. Note the boundaries:
- **Autonomous**: what you can do without asking
- **Notify**: what you can do but must report
- **Approve**: what requires human sign-off before proceeding
- **Discuss**: what requires open conversation first

## 5. Ask for direction

Ask the human what they want to focus on this session. If there are
in-progress items, mention them as natural candidates. If there are
blocked items, flag them.
