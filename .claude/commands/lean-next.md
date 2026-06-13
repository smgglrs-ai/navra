# Pick Next Task

Select and start the next plan item to work on.

## Steps

### 1. Load current state

Read `.lean/plan.yml` and identify:
- All items with `status: planned`
- All items with `status: done` (needed for dependency resolution)
- Any items with `status: in_progress` (warn if work is already active)

### 2. Filter for unblocked items

An item is unblocked when all IDs in its `depends_on` list have
`status: done`. Remove blocked items from candidates.

### 3. Prioritize

Sort candidates by:
1. Priority: critical > high > medium > low
2. ID (lower first, as earlier items often set up context for later ones)

### 4. Autonomy pre-check

Read `.lean/project.yml` `autonomy` section. Check the candidate's
`scope` against autonomy boundaries:

- If scope is fully within **autonomous** or **notify**: proceed.
- If scope touches **approve** or **discuss**: inform the human
  that this item will need approval/discussion and ask if they
  want to start it anyway.

### 5. Start the item

1. Set the candidate's `status` to `in_progress` and `progress` to `0`
   in `.lean/plan.yml`
2. Present a brief summary of the item: title, description, scope,
   and acceptance criteria (if any)
3. Ask the human if they want to proceed or pick a different item
