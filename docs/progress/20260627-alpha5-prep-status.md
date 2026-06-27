# v0.6.0-alpha.5 Prep Status

Date: 2026-06-27

## Result

This branch prepares `v0.6.0-alpha.5` after the HSE2 GUI inspect action landed on `master`.

## Scope

The alpha.5 prep is centered on release metadata and validation notes for the standalone HSE2 GUI inspect workflow.

Included changes:

- bump Python package version from `0.6.0a4` to `0.6.0a5`;
- update Windows EXE documentation for `v0.6.0-alpha.5`;
- update the Windows EXE workflow dispatch default tag to `v0.6.0-alpha.5`;
- update the release checklist to require GUI inspect smoke validation;
- document that GUI inspect must show raw JSON plus a metadata-only readable summary.

## Included HSE2 GUI inspect behavior

The GUI inspect action should:

- expose the `inspect` action as `检查 HSE2 元数据`;
- build `hse2-inspect --input <ARCHIVE_PATH>` from the GUI state;
- route `hse2-inspect` through the standalone HSE2 GUI launcher in-process helper dispatch;
- keep raw JSON stdout visible in the log;
- append a safe metadata-only summary for inspect output;
- avoid decrypting the manifest, decrypting payload chunks, unlocking archive contents, or printing wrapper material.

## Expected Windows EXE set

The alpha.5 Windows zip should contain these executables:

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

Run locally before creating the alpha.5 tag:

```powershell
python -m compileall -q src tests build_tools
python -m unittest tests.test_hse2_gui_actions
python -m unittest tests.test_hse2_gui_tab
python -m unittest tests.test_hse2_gui_launcher
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

Also validate the installed entry points:

```powershell
pip install -e .
high-security-encryptor-hse2-gui --help
high-security-encryptor-hse2-inspect --help
```

## Manual GUI smoke target

Use a disposable `.hse2` file:

```powershell
python -m high_security_encryptor.hse2_gui_launcher
```

Select `检查 HSE2 元数据`, provide the `.hse2` input path, and confirm the log shows:

- raw JSON stdout from `hse2-inspect`;
- a readable `结果摘要` block;
- only metadata fields such as container path, format version, container size, wrapper count/types, payload chunk count, manifest encrypted status, and access-destroyed status.

## Status

This is alpha.5 prep only. Create the alpha.5 tag only after local validation, GUI smoke validation, CI checks, and Windows EXE artifact verification pass.
