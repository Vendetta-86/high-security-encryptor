# High Security Encryptor

High Security Encryptor is a local file-encryption tool for high-value data workflows. It supports streaming file encryption, batch sidecar artifacts, folder packages, runtime password providers, local brute-force throttling, and CLI-driven encryption/decryption plans.

## Install

```bash
python -m pip install -e .
high-security-encryptor --help
```

Python 3.11 or newer is required.

## Windows EXE

Windows release assets are published as zip files on GitHub Releases. Download
the `high-security-encryptor-<tag>-windows-x64.zip` asset, extract it, and run:

```powershell
.\high-security-encryptor.exe --help
.\high-security-encryptor-gui.exe
```

Double-clicking the executable shows help and keeps the console open on Windows.
Double-clicking `high-security-encryptor-gui.exe` opens the Chinese GUI for config validation,
batch encryption, batch decryption, removable-storage BitLocker management,
and example config generation.

## Run Tests

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src tests
python -m unittest discover -s tests
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

The test suite currently contains 187 tests, including installation smoke tests for the console and GUI scripts. The install smoke tests are skipped when the package has not been installed. The dev checks also run committed-secret scanning and Python dependency auditing.

## CLI

```bash
python -m high_security_encryptor encrypt-batch --config examples/compatible_encrypt.json
python -m high_security_encryptor decrypt-batch --config examples/compatible_decrypt.json
python -m high_security_encryptor init-example --mode hardened --kind decrypt --output decrypt.json
python -m high_security_encryptor init-example --mode compatible --kind encrypt --print
python -m high_security_encryptor validate-config --kind encrypt --config examples/hardened_encrypt.json
python -m high_security_encryptor validate-config --kind decrypt --config examples/no_password_tables_decrypt.json --strict
```

After installation, the console script is equivalent:

```bash
high-security-encryptor validate-config --kind encrypt --config examples/compatible_encrypt.json --report
high-security-encryptor-gui --smoke-test
```

## Password Sources

Password fields can be written as direct strings or provider objects:

```json
"metadata_password": "direct-password"
"metadata_password": {"type": "literal", "value": "direct-password"}
"metadata_password": {"type": "env", "name": "HSE_METADATA_PASSWORD"}
"metadata_password": {"type": "prompt", "prompt": "Metadata password: "}
"metadata_password": {"type": "file", "path": "C:/protected/metadata.txt"}
"metadata_password": {"type": "command", "argv": ["python", "-c", "print('example-pass')"]}
```

The `command` provider accepts only an explicit `argv` array and does not invoke a shell.
GUI-generated configs use `env` providers by default so typed passwords are not saved as JSON literals.

## Security Modes

Three named modes are supported:

- `compatible`: writes top-level and internal password-table sidecars.
- `hardened`: omits the top-level password table but keeps internal folder password tables.
- `no-password-tables`: omits all password tables and relies on templates plus runtime providers.

Explicit `write_password_table` or `write_internal_password_tables` values override the named mode defaults.

When `security_mode` is omitted, new encryption configs default to `no-password-tables`. If an encryption config explicitly asks for a password table path or explicitly enables password-table output, it is treated as compatible intent. For decryption configs without `security_mode`, a present `password_table_path` keeps legacy compatible behavior; otherwise the config defaults to `no-password-tables`.

For decrypt configs in `hardened` or `no-password-tables` mode, omit `password_table_path` and provide passwords through `template_passwords_by_encrypted_name`, `template_passwords_by_source_name`, or folder runtime template mappings.

## Brute-force Guard

`decrypt-batch` enables local failed-attempt throttling by default. Integrity or authentication failures are counted per decryption plan. After 5 failures within 15 minutes, the same plan is locked for 30 minutes. Successful decryption clears that plan's failure history.

Useful options:

```bash
high-security-encryptor decrypt-batch --config decrypt.json \
  --brute-force-max-failures 5 \
  --brute-force-window-seconds 900 \
  --brute-force-lock-seconds 1800
```

Additional controls:

- `--brute-force-guard-state PATH`: use a specific local guard-state file.
- `--disable-brute-force-guard`: disable local throttling for one run.
- `HSE_BRUTE_FORCE_GUARD_STATE`: environment override for the default state path.

This is a local online-attack throttle. It does not make a copied encrypted file impossible to attack offline, so strong passwords and hardened/no-password-table workflows remain necessary.

## Security and Operations

- [Security Model](docs/security_model.md): protection goals, non-goals, sidecar sensitivity, and provider risks.
- [Operational Guidance](docs/operations.md): recommended modes, backup handling, password handling, rotation, and failure response.
- [KDF Profiles](docs/kdf_profiles.md): Argon2id profile compatibility, hardened/paranoid roadmap, and HSE2 direction.
- [Phase 3 Completion](docs/phase3_completion.md): hardening, modularization, verification baseline, and compatibility notes.
- [Phase 4 Completion](docs/phase4_completion.md): release readiness scope and verification baseline.
- [Phase 5 Completion](docs/phase5_completion.md): GUI quick-use improvements and Windows removable-storage encryption support.
- [Release Checklist](docs/release_checklist.md): final verification steps before tagging or publishing.
- [Windows EXE Distribution](docs/windows_exe.md): PyInstaller build and release-asset notes.

Folder encryption streams ZIP data directly into encrypted output instead of writing a temporary plaintext ZIP. Folder decryption still needs a temporary plaintext ZIP for standard ZIP extraction; set `HSE_TEMP_DIR` to place those temporary files on a controlled local volume.

## Exit Codes

CLI failures are normalized into stable exit codes:

- `0`: command completed successfully
- `1`: runtime workflow failure
- `2`: `validate-config --report --exit-code-on-issues` found report issues
- `3`: command input or config file error
- `4`: password-source provider error
- `5`: integrity or authentication failure
- `6`: brute-force guard lockout

By default, CLI errors are printed as concise `error: ...` messages without Python tracebacks. Use `--debug` before the subcommand, or set `HSE_DEBUG=1`, to print full tracebacks:

```bash
high-security-encryptor --debug validate-config --kind encrypt --config config.json
```

## Troubleshooting

- `error: ... config file not found`: check the `--config` path.
- `error: ... config is not valid JSON`: validate the config file syntax.
- `error: environment variable not set`: set the named password-provider environment variable before running the command.
- `error: chunk authentication failed` or another integrity error: verify the password, encrypted file, manifest, template, and password table all belong to the same batch.
- `error: too many failed decryption attempts`: wait for the displayed retry interval, verify that the config and encrypted artifacts belong together, then retry with the correct password.

## Project Layout

- `src/high_security_encryptor/`: implementation package
- `tests/`: unit and integration tests
- `examples/`: example JSON configs for each security mode
- `docs/`: format and batch-binding notes
- `.pre-commit-config.yaml` and `.secrets.baseline`: local committed-secret scanning
- `.github/workflows/ci.yml`: Windows CI for Python 3.11, 3.12, and 3.13

## Current Status

- Streaming file encryption format is implemented.
- Legacy `GCM1` decryption compatibility is implemented.
- Batch binding, encrypted sidecars, and mixed file/folder workflows are implemented.
- Mixed batch decryption and folder auto-decryption are implemented.
- Runtime password providers and no-password-table flows are implemented.
- JSON config validation and report output are implemented.
- Local brute-force throttling is enabled for CLI batch decryption.
- Argon2id KDF profiles are documented for HSE1 compatibility and future HSE2 self-describing containers.
- Third-stage hardening, modularization cleanup, and focused helper coverage are complete.
- Fourth-stage release readiness work is complete for version `0.2.0`.
- Windows executable release automation is available for version `0.2.1`.
- Windows double-click help behavior is fixed for version `0.2.2`.
- GUI release automation is available for version `0.3.0`.
- Chinese GUI text is available for version `0.3.1`.
- GUI function names now use clearer task-oriented Chinese labels.
- GUI quick-use mode is available for no-config one-click encryption and decryption.
- GUI quick-use mode supports dragging files or folders into the path field.
- GUI file encryption/decryption tabs include easy multi-file setup, bundled multi-file encryption, and per-file or per-folder-inner passwords.
- Windows removable-storage encryption is available for version `0.4.0` through a dedicated BitLocker To Go GUI tab.
