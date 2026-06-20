# v0.6.0-alpha.4 Prep Status

Date: 2026-06-20

## Result

This branch prepares `v0.6.0-alpha.4` after the HSE2 inspect CLI landed on `master`.

## Scope

The alpha.4 prep is centered on the new read-only HSE2 inspect helper and packaging notes.

Included changes:

- bump Python package version from `0.6.0a3` to `0.6.0a4`;
- update Windows EXE documentation for `v0.6.0-alpha.4`;
- document that the Windows zip includes the inspect helper executable;
- update the checklist to include inspect help and metadata checks;
- update the Windows EXE workflow dispatch default tag to `v0.6.0-alpha.4`.

## Expected Windows EXE set

The alpha.4 Windows zip should contain these executables:

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

Run locally before creating the alpha.4 tag:

```powershell
python -m compileall -q src tests build_tools
python -m unittest tests.test_hse2_inspect_cli
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

Also validate the new CLI entrypoint:

```powershell
pip install -e .
high-security-encryptor-hse2-inspect --help
```

For a disposable `.hse2` file, validate metadata output:

```powershell
high-security-encryptor-hse2-inspect --input .\archive.hse2
```

## Status

This is alpha.4 prep only. Create the alpha.4 tag only after local validation and CI checks pass.
