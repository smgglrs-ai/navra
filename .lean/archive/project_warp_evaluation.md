---
name: Warp fork evaluation
description: Warp terminal open-sourced 2026-04-29; MIT UI crates have AGPL contamination; adopt patterns not code
type: project
originSessionId: 01056850-a7e7-425e-a084-bbde88c4dd3d
---
Warp (warpdotdev/warp) open-sourced client 2026-04-29 under AGPL-3.0.
warpui_core + warpui crates are MIT-licensed but depend on 4 AGPL
internal crates (markdown_parser, string-offset, sum_tree, warp_util),
making extraction impractical without AGPL contamination.

**Decision**: Adopt Warp's UX *patterns* via clean-room re-implementation
(Phase 8 in ROADMAP.md), not fork the code. Key patterns: action/result
enum symmetry, MCP config import, config schema generation, Actor trait
for computer use, isolation detection.

**Why:** The warpui framework is 102K lines, GPU-accelerated (wgpu),
production-quality — but the license contamination, 2 forked deps
(cosmic-text, dwrote-rs), and heavy platform coupling make extraction
cost exceed re-implementation cost on a cleaner base (e.g., iced).

**How to apply:** Phase 8 items in ROADMAP.md. Highest value: typed
agent action model (8a) and MCP config import (8b).
