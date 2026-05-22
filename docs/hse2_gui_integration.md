# HSE2 GUI Integration Boundary

HSE2 remains an explicit experimental workflow. The GUI integration starts with a
small command-builder boundary instead of duplicating HSE2 workflow logic in the
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

The intended GUI flow is:

1. collect paths/options in Tkinter widgets;
2. call `build_hse2_gui_command(...)`;
3. pass the returned argv to the existing GUI CLI runner;
4. show captured stdout/stderr in the existing GUI log.

## Why This Boundary Exists

The CLI already owns the HSE2 behavior, validation, provider handling, DPAPI
handling, and JSON summaries. Reusing the CLI path avoids a second HSE2
implementation in the GUI and keeps future fixes centralized.

## Explicit Non-goals

This boundary does not yet add a visible HSE2 tab to the Tkinter window. That
should be a follow-up PR that only wires widgets to these command builders.

It also does not:

- introduce in-place HSE2 operations;
- bypass existing provider parsing;
- store wrapper material in GUI state beyond normal widget values;
- print keyfile, DPAPI, or wrapper bytes;
- change HSE1/HSE2 defaults.

## Follow-up GUI Tab Plan

A future GUI PR should add a new `HSE2 实验` tab with compact sections:

1. run HSE2 encrypt/decrypt config;
2. run HSE2 validation config;
3. generate keyfile;
4. protect keyfile with Windows DPAPI;
5. run HSE2 keyfile rotation config.

Each button should use `build_hse2_gui_command(...)` and then call the existing
GUI `_run_cli(...)` method.
