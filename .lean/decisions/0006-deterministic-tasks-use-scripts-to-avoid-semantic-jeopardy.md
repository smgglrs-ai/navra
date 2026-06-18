---
title: Deterministic tasks use scripts to avoid semantic jeopardy
date: 2026-06-18
status: accepted
source: session 941834
---

Tasks that are deterministic (file moves, plan regeneration, permission setup, session filtering) must use shell scripts under .lean/scripts/, not LLM semantic processing. The user stated (MSG 963): 'Let's make sure we have scripts for deterministic tasks, so we don't have semantic jeopardy.' LLM agents are reserved for tasks requiring judgment (extracting meaning from sessions, analyzing code patterns).
