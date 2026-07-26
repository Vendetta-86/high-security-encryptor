# v0.6.0-alpha.6 Prep Status

Date: 2026-07-04

## Result

This branch prepares `v0.6.0-alpha.6` after the HSE2 GUI dynamic field visibility work landed on `master`.

## Scope

The alpha.6 prep is centered on release metadata and validation notes for action-specific HSE2 GUI field visibility.

Included changes:

- bump Python package version from `0.6.0a5` to `0.6.0a6`;
- update Windows EXE documentation for `v0.6.0-alpha.6`;
- update the Windows EXE workflow dispatch default tag to `v0.6.0-alpha.6`;
- update the release checklist to require HSE2 GUI dynamic field smoke validation;
- document that the standalone HSE2 GUI should hide fields that are not relevant to the selected action.

## Included HSE2 GUI behavior

The standalone HSE2 GUI should:

- show only the config path for config-driven actions;
- show config path plus validation report/summary options for `validate`;
- show only the `.hse2` input path for `inspect` and `wrapper-list`;
- show output path, keyfile size, and overwrite for `generate-keyfile`;
- show input path, output path, DPAPI scope, and overwrite for `dpapi-protect`;
- show wrapper id plus optional password/keyfile/DPAPI fields for `wrapper-remove`;
- show the exact confirmation field and warning phrase for `access-destroy`.

## Expected Windows EXE set

The alpha.6 Windows zip should contain these executables:

- `high-security-encryptor.exe`
- `high-security-encryptor-gui.exe`
- `high-security-encryptor-hse2-gui.exe`
- `high-security-encryptor-hse2-create.exe`
- `high-security-encryptor-hse2-open.exe`
- `high-security-encryptor-hse2-header-backup.exe`
- `high-security-encryptor-hse2-inspect.exe`
- `high-security-encryptor-hse2-wrapper.exe`
- `high-security-encryptor-hse2-access.exe`

## Validation gate

Run locally before creating the alpha.6 tag:

```powershell
python -m compileall -q src tests build_tools
python -m unittest tests.test_hse2_gui_tab
python -m unittest tests.test_hse2_gui_actions
python -m unittest tests.test_hse2_gui_launcher
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

## Manual GUI smoke target

Use the standalone HSE2 GUI:

```powershell
python -m high_security_encryptor.hse2_gui_launcher
```

Switch through the HSE2 action dropdown and confirm fields hide/show according to the selected action. Confirm `检查 HSE2 元数据` displays only the `.hse2` input field and still runs `hse2-inspect --input ...`.

## Status

This is alpha.6 prep only. Create the alpha.6 tag only after local validation, GUI smoke validation, CI checks, and Windows EXE artifact verification pass.
