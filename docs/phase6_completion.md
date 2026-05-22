# Phase 6 Completion: HSE2 Wrapper Providers, DPAPI, and Experimental GUI

Phase 6 adds local Windows hardening and HSE2 workflow usability around wrapper
material. The scope is intentionally explicit: HSE2 remains config-driven and
experimental, while the CLI continues to own the cryptographic workflow logic.

## Completed Scope

### Windows DPAPI Provider

- Added a Windows-only `dpapi` password-source provider.
- Added `dpapi-protect` for protecting local wrapper material.
- Supports `current_user` and `local_machine` DPAPI scopes.
- Refuses to overwrite DPAPI blob files by default unless `--force` is provided.
- Returns explicit unavailable-path errors on non-Windows systems.
- Does not print protected or unprotected wrapper bytes in CLI summaries.

### HSE2 DPAPI Workflow Coverage

- Added Windows DPAPI helper round-trip tests.
- Added CLI `dpapi-protect` round-trip tests.
- Added provider resolution tests.
- Added HSE2 encrypt/validate/decrypt workflow tests using the `dpapi` wrapper provider.

### HSE2 Wrapper Provider Documentation

Documented the supported HSE2 wrapper provider matrix:

- `literal`
- `env`
- `file`
- `keyfile`
- `dpapi`
- `command`
- `prompt`

Added smoke-tested HSE2 encrypt examples for wrapper providers.

### Experimental HSE2 GUI

- Added GUI-facing HSE2 command builders that delegate to existing CLI commands.
- Added a reusable `HSE2ExperimentalTab` component.
- Added a standalone `high-security-encryptor-hse2-gui` launcher.
- Added a main-GUI-facing helper for opening the standalone HSE2 window as a child window.
- Documented the future low-risk main-GUI button wiring point.

### Windows EXE Packaging

- Added a PyInstaller entry point for the standalone HSE2 GUI launcher.
- Updated Windows EXE documentation and release checklist for the HSE2 GUI executable.
- Updated the Windows EXE release workflow to build and package:
  - `high-security-encryptor.exe`
  - `high-security-encryptor-gui.exe`
  - `high-security-encryptor-hse2-gui.exe`

## Verification Baseline

The work has been merged through focused PRs with CI passing on Windows for:

- Python 3.11
- Python 3.12
- Python 3.13

The CI gate includes:

- editable package install;
- committed-secret scan;
- dependency vulnerability audit;
- syntax check with `compileall`;
- full unittest suite;
- console script smoke test.

## Compatibility Notes

Phase 6 does not change existing HSE1 defaults, batch workflows, migration
behavior, validation behavior, bundle behavior, or existing main-GUI behavior.

The standalone HSE2 GUI uses existing CLI workflows. It does not reimplement
HSE2 cryptographic logic in the GUI layer.

## Non-goals

Not included in this phase:

- embedding the HSE2 tab directly into the main GUI notebook;
- a full HSE2 one-click wizard;
- automatic deletion of unprotected keyfiles after DPAPI protection;
- DPAPI optional entropy support;
- cross-machine portability for DPAPI blobs.

## Follow-up Work

Recommended next steps:

1. Add a visible main-GUI button that opens the standalone HSE2 experimental window.
2. Add an HSE2 wizard for keyfile generation, DPAPI protection, and example config creation.
3. Add a focused HSE2 threat-model document.
4. Perform a tagged Windows EXE release and verify the zip contains all three executables.
