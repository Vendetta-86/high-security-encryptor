# v0.6.0-alpha.8 Release Prep Status

Date: 2026-10-31

## Scope

This release-prep line follows the published `v0.6.0-alpha.7`. It packages the current HSE2 implementation for fresh CI and Windows executable validation. It does not create a Git tag or publish a GitHub Release.

## Included scope

- HSE2 v3 streaming container create/open with v2 compatibility.
- Archive validation helper executable and authenticated validation workflows.
- GUI create/open/validate flows, in-memory masked password entry, metadata preview, and create-to-restore navigation.
- Configurable restore staging via `HSE2_RESTORE_TEMP_DIR`, constrained to an existing directory on the same filesystem as the restore destination.
- Phase 8 decoy/duress remains deferred; this release makes no plausible-deniability claim.

## Release identifiers

- Git tag: `v0.6.0-alpha.8`
- Python package version: `0.6.0a8`
- Expected Windows asset: `high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip`
- Expected executable set: ten executables listed in `docs/windows_exe.md`.

## Completed local validation

- Full suite after the strict JSON integer parsing fix: 667 passed, 6 skipped. The regression test confirms JSON booleans are rejected for integer-valued HSE2 header fields.
- `compileall`, `pre-commit run --all-files`, `pip_audit . --progress-spinner off`: passed.
- Windows 11 x64 / Python 3.13.15 / PyInstaller 6.22.3: all 10 executables built; main CLI/GUI smoke, all helper `--help`, and config validation examples passed.
- Packaged EXE v3 create → inspect → standalone validate → validate-before-open → restore: passed; restored bytes matched and temporary restore directory was empty.
- Packaged HSE2 GUI: localized action labels and action-specific fields inspected; password entries masked; metadata inspection of a disposable v3 container exited 0 and showed the expected non-secret summary.
- Packaged GUI metadata inspection was repeated after rebuilding with the parsing fix: a disposable v3 container returned exit code 0 and showed the expected non-secret summary.
- Refreshed local ZIP: `dist/high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip`, 133,998,872 bytes, 16 entries (10 EXEs plus documentation/examples); contents checked.

The previously pushed candidate commit `6699036294fa5f9a7c6dc3aac4c972a0e041c74e` passed GitHub Actions run [41178052016](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41178052016), and roadmap commit `141c056240cb7fc117461e204cc665f75e7c244e` passed run [41179913657](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41179913657), each on Windows Python 3.11, 3.12, and 3.13. The local parsing fix and rebuilt artifacts documented above are newer and still require a fresh remote CI run. These CI results do not substitute for maintainer release review. The following commands are the reproducible local release gate when validating a clean candidate:

```powershell
python -m compileall -q src tests build_tools
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

The project venv used during prep is `work\hse2-test-venv`. Build and smoke each executable using the commands in `docs/windows_exe.md` and `.github/workflows/windows-exe.yml`; confirm archive create/inspect/validate/open round trip and byte-for-byte restored content.

## Remaining release gates

- Maintainer review of the release checklist, threat model, format and GUI/CLI behavior.
- A clean-checkout rerun of the local release gate if source code or build inputs differ from the tested candidate tree.

## Status

Local Windows candidate validation is complete, including a post-fix rebuild; fresh CI for the parsing fix and maintainer release review are outstanding. No tag or release has been created.
