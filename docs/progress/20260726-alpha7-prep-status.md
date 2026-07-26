# v0.6.0-alpha.7 Release Prep Status

Date: 2026-07-26

## Scope

`v0.6.0-alpha.7` is a release-prep step after the alpha.6 Windows EXE smoke found that the standalone HSE2 GUI action dropdown showed internal action keys, such as `encrypt-config`, instead of localized user-facing labels.

The alpha.7 release line includes the HSE2 GUI localized action-label fix from PR #78 and prepares a new Windows EXE build for validation.

## Changes prepared

- Python package version is bumped to `0.6.0a7`.
- The Windows EXE workflow dispatch default tag is updated to `v0.6.0-alpha.7`.
- Windows EXE documentation is updated for the alpha.7 artifact name.
- The release checklist now requires the HSE2 GUI action dropdown to show localized labels.
- The release checklist explicitly validates that `检查 HSE2 元数据` is visible and maps to the inspect action.

## Expected Windows artifact

```text
high-security-encryptor-v0.6.0-alpha.7-windows-x64.zip
```

## Required validation gate

Run before tagging or publishing:

```powershell
python -m compileall -q src tests build_tools
python -m unittest tests.test_hse2_gui_tab
python -m unittest tests.test_hse2_gui_actions
python -m unittest tests.test_hse2_gui_launcher
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

## Required Windows EXE smoke

After the alpha.7 Windows artifact is built, download and extract it, then confirm the executable set and run a disposable HSE2 round trip.

The final restored content should be:

```text
hello alpha7
```

Run the standalone HSE2 GUI executable:

```powershell
.\high-security-encryptor-hse2-gui.exe
```

Confirm:

- the action dropdown shows localized labels rather than internal action keys;
- `检查 HSE2 元数据` is present in the action dropdown;
- selecting `检查 HSE2 元数据` shows only the `.hse2` input field;
- running inspect against the disposable `alpha7.hse2` archive prints raw JSON;
- a readable metadata-only `结果摘要` appears below supported inspect JSON;
- no ciphertext, nonce, authentication tag, wrapped-key blob, keyfile bytes, or local key material is exposed.

Run the main GUI smoke:

```powershell
.\high-security-encryptor-gui.exe --smoke-test
```

Then launch the main GUI and confirm `打开 HSE2 实验工具` opens the HSE2 experimental window.

## Notes

The alpha.6 CLI round-trip smoke produced `hello alpha6`, but alpha.6 GUI validation was not accepted because the standalone HSE2 GUI exposed internal action keys. Alpha.7 supersedes alpha.6 for the Windows GUI validation path.

## Status

Release metadata for `v0.6.0-alpha.7` is prepared pending CI, tag creation, Windows EXE build, and Windows GUI smoke validation.
