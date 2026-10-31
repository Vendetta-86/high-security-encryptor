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

- Full suite after strict JSON integer validation across HSE2 headers, header-backup metadata, payload chunk indices, and archive manifests: 669 passed, 6 skipped. Regression tests confirm JSON booleans are rejected in those integer fields.
- `compileall`, `pre-commit run --all-files`, `pip_audit . --progress-spinner off`: passed.
- Windows 11 x64 / Python 3.13.15 / PyInstaller 6.22.3: all 10 executables built; main CLI/GUI smoke, all helper `--help`, and config validation examples passed.
- Packaged EXE v3 create → inspect → standalone validate → validate-before-open → restore: passed; restored bytes matched and temporary restore directory was empty.
- Packaged HSE2 GUI: localized action labels and action-specific fields inspected; password entries masked; metadata inspection of a disposable v3 container exited 0 and showed the expected non-secret summary.
- Packaged GUI metadata inspection was repeated after rebuilding with the parsing fix: a disposable v3 container returned exit code 0 and showed the expected non-secret summary.
- Rebuilt all ten executables from the expanded fix; CLI smoke checks and packaged v3 create/inspect/validate/open round trip passed again, with byte-identical restored content.
- Refreshed local ZIP: `dist/high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip`, 133,995,227 bytes, 16 entries (10 EXEs plus documentation/examples); contents checked.
- After commit `1d7e9f3` added the NIST-based per-DEK GCM payload invocation limit: full `unittest` discovery passed (671 tests, 6 skipped); `compileall`, `pre-commit run --all-files`, and `pip_audit . --progress-spinner off` passed. All ten Windows executables were rebuilt from this tree. Packaged CLI/GUI/helper help smoke checks passed, and packaged v3 create, inspect, standalone validation, validate-before-open, and byte-identical restore passed for three files including an empty file. The rebuilt HSE2 GUI metadata action reported format version 3, two payload chunks, and exit code 0.
- Clean-clone verification at `5d038c1ba357f73c362684045073fc71928c5339` imported source from `work\alpha8-clean-checkout-5d038c1\src`; `compileall`, pre-commit, and pip-audit passed, and full `unittest` discovery passed (671 tests, 4 skipped). GitHub CI run [41189557379](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41189557379) passed for this documentation commit.
- Refreshed the local candidate zip from the rebuilt executables and current release documentation: `dist/high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip`, 133,996,955 bytes, 16 entries including all 10 executables; archive entry list and executable count checked.

Candidate commit `6699036294fa5f9a7c6dc3aac4c972a0e041c74e`, roadmap commit `141c056240cb7fc117461e204cc665f75e7c244e`, initial parser fix `45e7e4cec5ce2bd598d6df02ed5d9bb7aaec3546`, and expanded integer-boundary fix `258607f2e6c209fd6de4940a9a436a4f794bb045` passed runs [41178052016](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41178052016), [41179913657](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41179913657), [41180527122](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41180527122), and [41180988674](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41180988674), respectively, on Windows Python 3.11, 3.12, and 3.13. The latest remote CI does not substitute for maintainer release review. The following commands are the reproducible local release gate when validating a clean candidate:

```powershell
python -m compileall -q src tests build_tools
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

The project venv used during prep is `work\hse2-test-venv`. Build and smoke each executable using the commands in `docs/windows_exe.md` and `.github/workflows/windows-exe.yml`; confirm archive create/inspect/validate/open round trip and byte-for-byte restored content.

## Remaining release gates

- Maintainer review of the release checklist, threat model, format and GUI/CLI behavior.

## Status

Local Windows candidate validation and clean-clone release gate are complete. Remote CI runs [41187598235](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41187598235) and [41189557379](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41189557379) passed on the GCM-limit code and latest progress record. Maintainer release review remains outstanding. No tag or release has been created.
