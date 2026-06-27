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
- `inspect` -> `hse2-inspect --input ...`
- `rotate-keyfile` -> `hse2-rotate-keyfile --config ...`
- `generate-keyfile` -> `generate-keyfile --output ... --size ... [--force]`
- `dpapi-protect` -> `dpapi-protect --input ... --output ... --scope ... [--force]`
- `wrapper-list` -> `hse2-wrapper list --input ...`
- `wrapper-remove` -> `hse2-wrapper remove --input ... --output ... --wrapper-id ... [--password-file ...] [--keyfile ...] [--dpapi] [--overwrite]`
- `access-destroy` -> `hse2-access destroy --input ... --output ... --confirm ... [--overwrite]`

## Reusable Experimental Tab Component

`high_security_encryptor.hse2_gui_tab` provides a reusable `HSE2ExperimentalTab`
component and `build_hse2_experimental_tab(...)` helper. The component collects
paths and options, calls the HSE2 command builders, and delegates execution to an
injected runner callback.

The tab exposes fields for inspect and wrapper/access workflows:

- `.hse2` input container path;
- output container path;
- wrapper id;
- password-file path;
- keyfile path;
- DPAPI unlock allowance;
- exact access-destroy confirmation phrase.

`inspect` only requires the `.hse2` input container path. It returns safe
container metadata and does not unlock the archive, decrypt the manifest, decrypt
payload chunks, or print raw wrapper material.

`wrapper-remove` and `access-destroy` display explicit confirmation dialogs before
execution. `access-destroy` also requires the exact irreversible-access-disable
confirmation phrase enforced by the access-management CLI.

## Standalone Launcher

The standalone HSE2 GUI launcher is available after installation:

```bash
high-security-encryptor-hse2-gui
```

It opens a compact `HSE2 实验工具` window with the reusable HSE2 experimental tab
and a log panel. The launcher delegates regular HSE2 actions through the same CLI
path used by the rest of the GUI, displays stdout/stderr/exit code, and prevents
concurrent HSE2 command execution.

The wrapper/access/inspect helper commands are standalone CLI entrypoints, so the
launcher routes `hse2-wrapper ...`, `hse2-access ...`, and `hse2-inspect ...` argv
lists directly to the corresponding in-process helper CLI main functions. This
keeps the GUI boundary explicit while still avoiding shelling out to sibling EXE
files.

Use this launcher for experimental HSE2 operations without changing the main GUI
window:

- HSE2 encrypt config;
- HSE2 decrypt config;
- HSE2 validation config;
- HSE2 metadata inspect;
- HSE2 keyfile rotation config;
- keyfile generation;
- Windows DPAPI protection;
- wrapper list;
- wrapper remove;
- explicit access-disable workflow.

## Result Summaries

The launcher keeps raw JSON stdout in the log for copy/paste debugging and also
adds a readable summary for selected HSE2 helper results.

`inspect` summaries include:

- input container path;
- format version;
- container size;
- wrapper count;
- wrapper types;
- payload chunk count;
- manifest encrypted status;
- access-destroyed status.

The summary is intentionally metadata-only and must not include ciphertext,
nonces, auth tags, wrapped-key blobs, or local key material.

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
