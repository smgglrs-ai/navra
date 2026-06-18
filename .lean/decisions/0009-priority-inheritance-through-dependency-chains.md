---
title: Priority inheritance through dependency chains
date: 2026-06-18
status: accepted
source: session 941834
---

The user raised whether priority should propagate through dependencies (MSG 2036): 'Isn't a medium priority item that is a dependency of a high priority item somehow inheriting the high priority?' This was accepted. When computing next work, a medium-priority item that blocks a high-priority item should be treated as effectively high priority.
