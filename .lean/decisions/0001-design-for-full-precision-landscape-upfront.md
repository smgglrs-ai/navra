---
title: Design for full precision landscape upfront
date: 2026-06-18
status: accepted
source: session 694274
---

When implementing GPU kernel features, design for the full precision landscape (FP32, FP16, BF16, FP8, FP4) from the start. Do not postpone FP4/FP8 variants. Rationale: they are core to the Blackwell value proposition, and designing only for FP16/FP32 first creates design biases that bite later when adding narrower formats. User explicitly said: 'We shouldn't postpone FP4/FP8 variants as they are part of the Blackwell value prop. And we should design for the full landscape to avoid design biases that bite us later.'
