---
title: Items are source of truth, plan.yml is generated
date: 2026-06-18
status: accepted
source: session 941834
---

Individual .lean/items/*.yml files are the source of truth for work items. plan.yml is a shallow generated index, regenerated from items by a script. The user identified redundancy (MSG 1609): 'Aren't some of the fields redundant with plan.yml? I'm fine having them in the item file, but we need to either have sync mechanism or move source of truth to item and make plan shallower.' Decision: items own the data, plan.yml is derived.
