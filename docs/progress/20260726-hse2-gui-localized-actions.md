# HSE2 GUI Localized Action Labels

Date: 2026-07-26

## Context

The alpha.6 Windows EXE CLI round-trip smoke passed with the expected restored content:

```text
hello alpha6
```

During the HSE2 GUI smoke, the action combobox showed internal action keys such as `encrypt-config` instead of localized user-facing labels. This made the documented `检查 HSE2 元数据` action difficult to discover even though the internal `inspect` action existed.

## Fix

The HSE2 experimental tab now keeps two values for the action selector:

- a localized display label shown in the combobox;
- a stable internal action key used to build CLI argv.

The mapping preserves compatibility with existing internal action keys while allowing user-facing labels such as `检查 HSE2 元数据` to appear in the GUI.

## Boundary

This fix does not change HSE2 cryptographic behavior, CLI argument semantics, archive format, wrapper handling, or access-destroy behavior. It is a GUI presentation and mapping fix only.

## Validation target

Run:

```powershell
python -m compileall -q src tests build_tools
python -m unittest tests.test_hse2_gui_tab
python -m unittest tests.test_hse2_gui_actions
python -m unittest tests.test_hse2_gui_launcher
python -m unittest discover -s tests
pre-commit run --all-files
```

Manual GUI smoke:

```powershell
python -m high_security_encryptor.hse2_gui_launcher
```

Confirm the action combobox shows localized labels, including `检查 HSE2 元数据`, and selecting that action only displays the `.hse2` input field.
