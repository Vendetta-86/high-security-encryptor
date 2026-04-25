# Release Checklist

Use this checklist before tagging or publishing a release.

## Version

- Confirm `pyproject.toml` has the intended version.
- Confirm README status and test count match the current test suite.
- Confirm release notes or completion docs describe the completed scope.

## Local Verification

Run:

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src tests
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
high-security-encryptor --help
```

Validate example configs:

```bash
python -m high_security_encryptor validate-config --kind encrypt --config examples/compatible_encrypt.json --report
python -m high_security_encryptor validate-config --kind decrypt --config examples/compatible_decrypt.json --report
python -m high_security_encryptor validate-config --kind encrypt --config examples/hardened_encrypt.json --report
python -m high_security_encryptor validate-config --kind decrypt --config examples/hardened_decrypt.json --strict --report
python -m high_security_encryptor validate-config --kind encrypt --config examples/no_password_tables_encrypt.json --report
python -m high_security_encryptor validate-config --kind decrypt --config examples/no_password_tables_decrypt.json --strict --report
```

Compatible-mode examples may emit warning issues because they intentionally generate or consume top-level password tables. Warnings are acceptable for those examples unless `--warnings-as-errors` is part of the release gate.

## CI

CI must pass on Windows for Python 3.11, 3.12, and 3.13.

The CI gate includes:

- editable package install
- committed-secret scan
- dependency vulnerability audit
- syntax check with `compileall`
- full unittest suite
- console script smoke test

## Windows EXE

For releases that include a Windows executable:

- Confirm the `Windows EXE` workflow passes for the release tag.
- Confirm the workflow uploads `high-security-encryptor-<tag>-windows-x64.zip`.
- Download and extract the zip.
- Run `high-security-encryptor.exe --help`.
- Run `high-security-encryptor-gui.exe --smoke-test`.
- Run at least one config validation with the executable.
- Confirm the executable zip contains no user config files, passwords, keys, or local build caches.

## Compatibility

Before release, verify these imports still work:

```python
from high_security_encryptor.config import BatchEncryptionConfig, BatchDecryptionConfig
from high_security_encryptor.batch_workflow import get_encrypted_target_path
from high_security_encryptor.folder_decryption import safe_extract_folder_archive
from high_security_encryptor.streaming_format import HEADER_MAGIC, IntegrityError
```

## GitHub

- Commit release-prep changes.
- Push the target branch.
- Confirm local branch and GitHub branch point to the same commit.
