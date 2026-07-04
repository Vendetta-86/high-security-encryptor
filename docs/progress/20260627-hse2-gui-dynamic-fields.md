# HSE2 GUI Dynamic Field Visibility

Date: 2026-06-27

## Result

This branch adds action-specific field visibility to the standalone HSE2 experimental GUI tab.

## Scope

The GUI now hides fields that are not relevant to the selected action while keeping the CLI command builders as the authoritative execution boundary.

Implemented visibility rules:

- config actions show only the config path;
- `validate` shows config path, optional report output, and validation flags;
- `inspect` shows only the `.hse2` input container path;
- `generate-keyfile` shows output path, keyfile size, and overwrite;
- `dpapi-protect` shows input path, output path, DPAPI scope, and overwrite;
- `wrapper-list` shows only the `.hse2` input container path;
- `wrapper-remove` shows input/output paths, wrapper id, optional password/keyfile/DPAPI fields, and overwrite;
- `access-destroy` shows input/output paths, overwrite, exact confirmation phrase, and the warning phrase.

## Boundary

This change only affects GUI field visibility. It does not:

- change any HSE2 CLI behavior;
- change command argv construction semantics;
- store key material outside normal widget state;
- print wrapper material or decrypted data;
- change HSE1/HSE2 defaults.

## Validation gate

Run locally before merge:

```powershell
python -m compileall -q src tests build_tools
python -m unittest tests.test_hse2_gui_tab
python -m unittest tests.test_hse2_gui_actions
python -m unittest tests.test_hse2_gui_launcher
python -m unittest discover -s tests
pre-commit run --all-files
```

## Manual GUI smoke target

```powershell
python -m high_security_encryptor.hse2_gui_launcher
```

Switch through the HSE2 action dropdown and confirm each action only displays its relevant fields. Confirm `inspect` displays only the `.hse2` input field and still runs `hse2-inspect --input ...`.
