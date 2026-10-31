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
- Packaged HSE2 GUI wrapper/access manual smoke on disposable v3 copies: wrapper list displayed two IDs and exited 0; wrapper removal confirmed explicitly and emitted a new container with one remaining wrapper (independently checked by packaged CLI); access destroy required the exact warning phrase plus a second confirmation, emitted a new container with `wrapper_count=0` and `access_destroyed=true`, and exited 0. Both source containers remain unchanged.
- Packaged HSE2 GUI add/rewrap smoke on disposable v3 copies: add produced a three-wrapper output with `gui-add-check`; rewrap replaced it with `gui-rewrap-check` while retaining a total of three wrappers. The packaged open CLI authenticated the rewrapped archive with the new independent keyfile using `--validate-before-open`; all three restored files, including the empty file, matched their source SHA-256 and lengths. The source archives were separate from each output. This is a manual packaged-GUI smoke, not automated cross-version GUI coverage.
- Packaged HSE2 GUI header-backup export to a separate disposable path succeeded with exit code 0; its output included the body digest, offset, size, and wrapper/chunk counts. An invalid `.json` suffix was rejected before writing, and the documented `.hse2.header` suffix succeeded. The packaged header-backup CLI restored a separate copy with body digest verification; its SHA-256 exactly matched the input archive. Packaged `validate-before-open` then authenticated header, manifest, and payload; opening with the original keyfile restored three files (including an empty file) with matching relative paths, lengths, and SHA-256 values. This is a manual packaged-GUI export plus packaged-CLI restore/open check.

## Current-source refresh after restore-path hardening

- Source commit: `4c3bb09101f113fb8a2c75adb5ab82471eed6603`; GitHub Actions run [41196270229](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41196270229) passed on Windows Python 3.11, 3.12, and 3.13.
- Windows 11 x64 / Python 3.13.15 / PyInstaller 6.22.3: rebuilt all ten executables in the isolated local directory `work/alpha8-refresh-4c3bb09/dist`; all eight console entry points returned exit code 0 for `--help`, and the main GUI `--smoke-test` passed. The standalone HSE2 GUI was built but not manually opened during this refresh.
- The rebuilt packaged v3 CLI created an archive with a 64 KiB chunk size, standalone archive validation passed, `validate-before-open` passed, and restore reproduced three files (including a zero-byte file and a multi-chunk file) with matching SHA-256 values.
- Packaged open rejected a validly authenticated test archive containing a noncanonical `./` path and another with Windows case-colliding names; both returned exit code 2 before creating the restore directory.
- Refreshed local candidate ZIP: `work/alpha8-refresh-4c3bb09/high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip`, 16 entries, 133,999,429 bytes. All ten EXE hashes inside the ZIP match the isolated build outputs. SHA-256: `47915a4d21c2230761499464b44a3df9d19df77587eccfefc5c1c86e5e199eb0`.
- This refreshed ZIP is a local verification artifact; it was not copied over the earlier `dist` candidate and no tag or GitHub Release was created. Maintainer release review remains outstanding.

## Current-source refresh after Windows filename restrictions

- Source commit: `9caf7fe62f078803ea531ef5214e0becd5cd3a7c`; GitHub Actions run [41197355242](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41197355242) passed on Windows Python 3.11, 3.12, and 3.13.
- Windows 11 x64 / Python 3.13.15 / PyInstaller 6.22.3: rebuilt all ten executables in `work/alpha8-refresh-9caf7fe/dist`. Eight console entry points passed `--help`; the main GUI `--smoke-test` passed. The standalone HSE2 GUI was built but not manually opened during this refresh.
- Packaged v3 create, standalone validate, and `validate-before-open` restore passed for three files, including an empty file and a multi-chunk binary; restored SHA-256 values matched.
- Packaged open rejected seven authenticated archives containing Windows alternate-data-stream syntax, reserved device names (including superscript COM/LPT variants), forbidden filename characters, or trailing ASCII spaces/periods. Every rejection returned exit code 2 before the restore directory was created.
- Refreshed ZIP: `work/alpha8-refresh-9caf7fe/high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip`, 16 entries, 134,010,611 bytes; all ten bundled executable hashes match build outputs. SHA-256: `29d56e28d34903c6e114c9bd6311ce1b050ec085ca5c5199a0654a6f96744cef`.
- The ZIP remains a local verification artifact; the earlier `dist` candidate was not overwritten. No tag or GitHub Release was created, and maintainer release review remains outstanding.

Candidate commit `6699036294fa5f9a7c6dc3aac4c972a0e041c74e`, roadmap commit `141c056240cb7fc117461e204cc665f75e7c244e`, initial parser fix `45e7e4cec5ce2bd598d6df02ed5d9bb7aaec3546`, and expanded integer-boundary fix `258607f2e6c209fd6de4940a9a436a4f794bb045` passed runs [41178052016](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41178052016), [41179913657](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41179913657), [41180527122](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41180527122), and [41180988674](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41180988674), respectively, on Windows Python 3.11, 3.12, and 3.13. The latest remote CI does not substitute for maintainer release review. The following commands are the reproducible local release gate when validating a clean candidate:

```powershell
python -m compileall -q src tests build_tools
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

The project venv used during prep is `work\hse2-test-venv`. Build and smoke each executable using the commands in `docs/windows_exe.md` and `.github/workflows/windows-exe.yml`; confirm archive create/inspect/validate/open round trip and byte-for-byte restored content.

## Remaining release gates

- Tag-specific Windows EXE build and Actions artifact upload are complete for `v0.6.0-alpha.8` (run [41203971451](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41203971451)). The public GitHub Release and its uploaded asset remain unpublished; the workflow's publish job was skipped.

## Status

Local Windows candidate validation and clean-clone release gate are complete. Remote CI runs [41187598235](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41187598235) and [41189557379](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41189557379) passed on the GCM-limit code and latest progress record. Maintainer review is recorded below. Tag-specific build and artifact upload have since passed; public release publication remains outstanding.

## Maintainer review — 2026-10-31

**Decision: CONDITIONALLY APPROVED as the `v0.6.0-alpha.8` release candidate; public release is not approved yet.**

Reviewed source commit: `9caf7fe62f078803ea531ef5214e0becd5cd3a7c` (candidate code); documentation/head commit at review: `b57cf1a2565cab868e2cbaf4f5e21cdff88a8db8`.

- Reviewed the release checklist, HSE2 threat model, format/framing references, candidate change, and recorded CLI/package evidence. The Windows restore-path validation rejects platform-invalid path components before creating restore outputs; no correctness, security, architecture, or performance blocker was found in the reviewed change.
- Confirmed the documented boundaries: HSE2 remains experimental; v3 is explicit while v2 remains the default; DPAPI is bound to the current Windows protection context; header backups do not replace unlock factors; plausible deniability and secure deletion are not claimed.
- The candidate source commit's Windows Python 3.11/3.12/3.13 CI run [41197355242](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41197355242) passed. The documentation/head commit's corresponding three-version run [41197607726](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41197607726) passed.
- Refreshed local candidate: `work/alpha8-refresh-9caf7fe/high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip`, 134,010,611 bytes, 16 entries; all ten bundled executable hashes match their build outputs. SHA-256: `29d56e28d34903c6e114c9bd6311ce1b050ec085ca5c5199a0654a6f96744cef`.
- On the packaged candidate, DPAPI v3 create and open succeeded for an empty file and a 200,000-byte multi-chunk file; restored relative paths, lengths, and SHA-256 values matched. Latest standalone HSE2 GUI metadata inspection and wrapper listing both exited 0 on this disposable archive; metadata showed format version 3, one DPAPI wrapper, four payload chunks, and no access-destroyed marker.
- The tag-specific Windows EXE workflow has not run and its tag-triggered publication/upload has not been verified. GitHub currently returns 404 for both the `v0.6.0-alpha.8` tag ref and release. Therefore this is candidate approval only, not approval to publish or a claim that the final tag asset exists.

## Windows executable workflow verification — 2026-10-31

- Workflow hardening source: `43abbb6f9d4bdb8d4924eb686a57a77bf034541a`. Its Windows Python 3.11/3.12/3.13 CI passed.
- On Windows 11 x64 / Python 3.13.15 / PyInstaller 6.22.3, mirrored the `windows-exe.yml` build job into `work/workflow-build-only-43abbb6`; all source gates passed: `detect-secrets`, `pip_audit` (no known vulnerabilities), `compileall`, and full `unittest` discovery (680 tests, 6 skipped).
- Built all ten executables. Main CLI help and hardened config validation passed; main GUI smoke and seven helper CLI help checks passed. The packaged GUI interaction checks are recorded below.
- Created a local v3 archive with an empty file and a 180,123-byte multi-chunk file using packaged EXEs. Create-time authentication, standalone archive validation, `validate-before-open` restore, and per-file SHA-256 comparison passed.
- Local build-only ZIP: `work/workflow-build-only-43abbb6/high-security-encryptor-workflow-smoke-43abbb6-windows-x64.zip`, 16 entries including ten EXEs, 134,014,063 bytes; SHA-256 `595c589e97614d79009aafdd7e2675e9146ae208e5058f7c997f3756293c215e`.
- Manual workflow-dispatch build run [41203128076](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41203128076) on commit `5935f76038683f76aebc8557f5891ecae29628e6` built successfully; its publish job was skipped. Artifact digest: `sha256:9fdeaf7a3526778501d6a65b26cd561183375ee43b79e6989d92676e2be20fec`.
- Annotated tag `v0.6.0-alpha.8` points to `5935f76038683f76aebc8557f5891ecae29628e6`. Tag run [41203971451](https://github.com/Vendetta-86/high-security-encryptor/actions/runs/41203971451) completed successfully: all 16 build/package/upload steps passed; the publish job was skipped. Artifact `high-security-encryptor-v0.6.0-alpha.8-windows-x64.zip` is 146,975,410 bytes with digest `sha256:1285232a49f201d03ebc7ecd2be8aa55c3b2864d835328e5cc679c8b30d4d5ee`.
- The Actions workflow artifact is not a GitHub Release. Public release publication and a publicly downloadable Release asset remain outstanding.

## Standalone HSE2 GUI verification and fix — 2026-10-31

- On the original packaged HSE2 GUI, selecting “永久禁用 HSE2 访问”, entering a wrong phrase, and confirming the disposable-output warning produced no output archive. Source archive remained 181,749 bytes with SHA-256 `3A7DFF495D372CE02159BC5AD2B0EA7E701993925FCCD5759F6C26B1CB8A8CBB`.
- That interaction exposed a UX issue: plan validation raised `ValueError` before the GUI's existing runner error handler, so the user received no visible mismatch message. The fix moves plan creation into the GUI error boundary and displays `输入无效` with the validation message. A regression test checks the message, blocks runner invocation, and verifies password fields are cleared.
- Packaged the updated standalone GUI in the isolated directory `work/gui-access-guard-validation`; executable SHA-256: `D507E69D1CC58FC7240F8F1BDECC583E4DF38CE16A36748A983E65A75AD4ECC9` (16,278,853 bytes). All 38 `tests.test_hse2_gui_tab` tests passed.
- Manual packaged-GUI negative path now visibly reports `永久禁用访问确认短语不匹配。`; no output archive was created. The source archive remained unchanged.
- Manual packaged-GUI positive path used the same disposable source and a distinct output. The GUI reported exit code 0, removed wrapper count 1, and `access_destroyed: true`. Packaged metadata inspection confirmed `access_destroyed=true`, `wrapper_count=0`, no wrappers, and three payload chunks. The source archive still inspects as `access_destroyed=false`, `wrapper_count=1`.
- The GUI validation fix is a local uncommitted change after the `v0.6.0-alpha.8` tag. It must pass the repository-wide local gates and remote CI before being considered part of a future release candidate. No public release was created.
