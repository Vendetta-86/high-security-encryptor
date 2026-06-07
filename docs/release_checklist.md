# Release Checklist

Use this checklist before tagging or publishing a release.

## Version

- Confirm `pyproject.toml` has the intended version.
- For version `0.5.2`, use release tag `v0.5.2`.
- Confirm README status and test coverage notes match the current test suite.
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
high-security-encryptor-gui --smoke-test
high-security-encryptor-hse2-gui --help
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

## HSE2 Documentation Review

Before release, review `docs/hse2_threat_model.md` against the shipped HSE2 behavior. Confirm it still matches:

- wrapper factors and portability boundaries;
- Windows DPAPI behavior;
- header backup and body-offset recovery metadata;
- quickstart workspace generation and one-click execution;
- wrapper remove and explicit access destruction behavior;
- release artifact exclusions for user-generated files.

## HSE2 CLI Verification

Run help checks for the focused HSE2 CLI entry points:

```bash
high-security-encryptor-hse2-create --help
high-security-encryptor-hse2-open --help
high-security-encryptor-hse2-header-backup --help
high-security-encryptor-hse2-wrapper --help
high-security-encryptor-hse2-access --help
```

Run at least one portable keyfile archive round trip before release. Replace angle-bracketed values with local validation paths:

```bash
high-security-encryptor-hse2-create \
  --root <ROOT_PATH> \
  --output <ARCHIVE_PATH> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret

high-security-encryptor-hse2-open \
  --input <ARCHIVE_PATH> \
  --output-dir <RESTORE_DIR> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret
```

Run at least one header backup export/restore check:

```bash
high-security-encryptor-hse2-header-backup export \
  --input <ARCHIVE_PATH> \
  --output <HEADER_BACKUP_PATH>

high-security-encryptor-hse2-header-backup restore \
  --input <ARCHIVE_PATH> \
  --backup <HEADER_BACKUP_PATH> \
  --output <RESTORED_ARCHIVE_PATH>
```

Run at least one wrapper list/remove check:

```bash
high-security-encryptor-hse2-wrapper list \
  --input <ARCHIVE_PATH>

high-security-encryptor-hse2-wrapper remove \
  --input <MULTI_WRAPPER_ARCHIVE_PATH> \
  --output <WRAPPER_REMOVED_ARCHIVE_PATH> \
  --wrapper-id <WRAPPER_ID> \
  --keyfile <KEYFILE_PATH>  # pragma: allowlist secret
```

Run at least one explicit access destruction check against a disposable fixture:

```bash
high-security-encryptor-hse2-access destroy \
  --input <DISPOSABLE_ARCHIVE_PATH> \
  --output <DESTROYED_ARCHIVE_PATH> \
  --confirm "I UNDERSTAND THIS WILL MAKE THE DATA PERMANENTLY UNRECOVERABLE"
```

On Windows release validation machines, also run one explicit DPAPI create/open round trip:

```bash
high-security-encryptor-hse2-create \
  --root <ROOT_PATH> \
  --output <DPAPI_ARCHIVE_PATH> \
  --dpapi

high-security-encryptor-hse2-open \
  --input <DPAPI_ARCHIVE_PATH> \
  --output-dir <DPAPI_RESTORE_DIR> \
  --dpapi
```

## CI

CI must pass on Windows for Python 3.11, 3.12, and 3.13.

The CI gate includes:

- editable package install
- committed-secret scan
- dependency vulnerability audit
- syntax check with `compileall`
- focused HSE2 create/open CLI tests
- full unittest suite
- console script smoke test

## Windows EXE

For releases that include a Windows executable:

- Confirm the `Windows EXE` workflow passes for the release tag.
- Confirm the workflow uploads `high-security-encryptor-v0.5.2-windows-x64.zip`.
- Download and extract the zip.
- Run `high-security-encryptor.exe --help`.
- Run `high-security-encryptor-gui.exe --smoke-test`.
- Confirm `high-security-encryptor-hse2-gui.exe` exists in the extracted zip.
- Confirm HSE2 CLI entry points are available from the extracted package or bundled console executable strategy.
- Run at least one config validation with the executable.
- Confirm the executable zip contains no user credential files, wrapper material, DPAPI blobs, or local build caches.

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
