# smgglrs-modal-vision

Vision module for the smgglrs gateway (image understanding, screen capture).

## Overview

Provides image and screen understanding through the gateway. Screen
capture uses the XDG Desktop Portal (`org.freedesktop.portal.Screenshot`),
which works on both Wayland and X11 and shows a system consent dialog.

Image understanding is delegated to vision-capable model backends
via `ModelBackend::generate` with image inputs.

## Key types

- `VisionModule` -- implements `Module` trait, registers vision tools
- `screenshot` module -- screen capture via D-Bus / XDG Desktop Portal
  - `capture_screen()` -- returns path to captured screenshot

## Dependency layer

```
smgglrs-core
    |
smgglrs-modal-vision
```

## Reference

See [DESIGN.md](../DESIGN.md) for the modality architecture and
[MODELS.md](../MODELS.md) for vision model support.
