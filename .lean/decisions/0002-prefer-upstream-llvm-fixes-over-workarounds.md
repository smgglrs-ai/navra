---
title: Prefer upstream LLVM fixes over workarounds
date: 2026-06-18
status: accepted
source: session 694274
---

When encountering LLVM backend limitations (e.g., intrinsic lowering bugs, register allocation issues), prefer contributing a fix to LLVM itself rather than building permanent workarounds in cuda-oxide. User said: 'I'd prefer needing a fix in LLVM itself.' Inline PTX asm is acceptable as a temporary workaround while the LLVM fix is developed.
