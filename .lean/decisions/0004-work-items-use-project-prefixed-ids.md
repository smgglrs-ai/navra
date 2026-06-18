---
title: Work items use project-prefixed IDs (NAVRA-XXX)
date: 2026-06-18
status: accepted
source: session 941834
---

Work item files under .lean/items/ use project-prefixed IDs like NAVRA-XXX instead of descriptive kebab-case names. The user pushed back on descriptive naming as 'over-prescribing' (MSG 1778) and proposed (MSG 1783): 'What other format wouldn't describe the what and be more neutral? Something like NAVRA-XXX? It could be decided during lean-init.' The prefix is set during lean-init per project.
