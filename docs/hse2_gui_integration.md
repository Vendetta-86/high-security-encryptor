# HSE2 GUI Integration Boundary

HSE2 remains an explicit experimental workflow. The GUI integration uses a small
command-builder boundary instead of duplicating HSE2 workflow logic in the
Tkinter layer.

## Implemented Boundary

`high_security_encryptor.hse2_gui_actions` exposes GUI-facing command builders
that convert validated GUI field values into existing CLI argv lists.

Supported actions:

- `encrypt-config` -> `hse2-encrypt-config --config ...`
- `decrypt-config` -> `hse2-decrypt-config --config ...`
- `validate` -> `hse2-validate --config ... [--output ...] [--summary-only] [--exit-code-on-failure]`
- `rotate-keyfile` -> `hse2-rotate-keyfile --config ...`
- `generate-keyfile` -> `generate-keyfile --output ... --size ... [--force]`
- `dpapi-protect` -> `dpapi-protect --input ... --output ... --scope ... [--force]`

## Reusable Experimental Tab Component

`high_security_encryptor.hse2_gui_tab` provides a reusable `HSE2ExperimentalTab`
component and `build_hse2_experimental_tab(...)` helper. The component collects
paths and options, calls the HSE2 command builders, and delegates execution to an
injected runner callback.

## Standalone Launcher

The standalone HSE2 GUI launcher is available after installation:

```bash
high-security-encryptor-hse2-gui
```

It opens a compact `HSE2 实验工具` window with the reusable HSE2 experimental tab
and a log panel. The launcher delegates execution through the same CLI path used
by the rest of the GUI, displays stdout/stderr/exit code, and prevents concurrent
HSE2 command execution.

Use this launcher for experimental HSE2 operations without changing the main GUI
window:

- HSE2 encrypt config;
- HSE2 decrypt config;
- HSE2 validation config;
- HSE2 keyfile rotation config;
- keyfile generation;
- Windows DPAPI protection.

## Main GUI Entry Helper

`high_security_encryptor.hse2_gui_entry` exposes `open_hse2_experimental_window(...)`.
It opens the standalone HSE2 experimental window as a child window and is the
preferred boundary for future main-GUI wiring.

The intended main-GUI button handler is:

```python
from .hse2_gui_entry import open_hse2_experimental_window

# inside HighSecurityEncryptorApp
open_hse2_experimental_window(self.master)
```

Keeping this helper separate avoids importing the HSE2 launcher at main-GUI module
import time and keeps the final `gui.py` wiring small.

## Why This Boundary Exists

The CLI already owns the HSE2 behavior, validation, provider handling, DPAPI
handling, and JSON summaries. Reusing the CLI path avoids a second HSE2
implementation in the GUI and keeps future fixes centralized.

## Explicit Non-goals

This boundary, tab component, standalone launcher, and main-GUI entry helper do not:

- introduce in-place HSE2 operations;
- bypass existing provider parsing;
- store wrapper material in GUI state beyond normal widget values;
- print keyfile, DPAPI, or wrapper bytes;
- change HSE1/HSE2 defaults.

## Follow-up Main GUI Wiring Plan

A follow-up PR can add a visible `打开 HSE2 实验工具` button to the main GUI by
importing `open_hse2_experimental_window` lazily from a button handler and passing
`self.master`. That PR should be intentionally small and only connect the existing
main window to the entry helper.
