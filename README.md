# High Security Encryptor

High Security Encryptor is a local file-encryption prototype for high-value data workflows. It supports streaming file encryption, batch sidecar artifacts, folder packages, runtime password providers, and CLI-driven encryption/decryption plans.

## Install

```bash
python -m pip install -e .
high-security-encryptor --help
```

Python 3.11 or newer is required.

## Run Tests

```bash
python -m unittest discover -s tests
```

The test suite currently contains 112 tests, including an installation smoke test for the `high-security-encryptor` console script. The smoke test is skipped when the package has not been installed.

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
```

## Password Sources

Password fields can be written as direct strings or provider objects:

```json
"metadata_password": "direct-password"
"metadata_password": {"type": "literal", "value": "direct-password"}
"metadata_password": {"type": "env", "name": "HSE_METADATA_PASSWORD"}
"metadata_password": {"type": "prompt", "prompt": "Metadata password: "}
"metadata_password": {"type": "file", "path": "C:/secrets/metadata.txt"}
"metadata_password": {"type": "command", "argv": ["python", "-c", "print('secret')"]}
```

The `command` provider accepts only an explicit `argv` array and does not invoke a shell.

## Security Modes

Three named modes are supported:

- `compatible`: writes top-level and internal password-table sidecars.
- `hardened`: omits the top-level password table but keeps internal folder password tables.
- `no-password-tables`: omits all password tables and relies on templates plus runtime providers.

Explicit `write_password_table` or `write_internal_password_tables` values override the named mode defaults.

For decrypt configs in `hardened` or `no-password-tables` mode, omit `password_table_path` and provide passwords through `template_passwords_by_encrypted_name`, `template_passwords_by_source_name`, or folder runtime template mappings.

## Security and Operations

- [Security Model](docs/security_model.md): protection goals, non-goals, sidecar sensitivity, and provider risks.
- [Operational Guidance](docs/operations.md): recommended modes, backup handling, password handling, rotation, and failure response.
- [Phase 3 Completion](docs/phase3_completion.md): hardening, modularization, verification baseline, and compatibility notes.

## Exit Codes

CLI failures are normalized into stable exit codes:

- `0`: command completed successfully
- `1`: runtime workflow failure
- `2`: `validate-config --report --exit-code-on-issues` found report issues
- `3`: command input or config file error
- `4`: password-source provider error
- `5`: integrity or authentication failure

By default, CLI errors are printed as concise `error: ...` messages without Python tracebacks. Use `--debug` before the subcommand, or set `HSE_DEBUG=1`, to print full tracebacks:

```bash
high-security-encryptor --debug validate-config --kind encrypt --config config.json
```

## Troubleshooting

- `error: ... config file not found`: check the `--config` path.
- `error: ... config is not valid JSON`: validate the config file syntax.
- `error: environment variable not set`: set the named password-provider environment variable before running the command.
- `error: chunk authentication failed` or another integrity error: verify the password, encrypted file, manifest, template, and password table all belong to the same batch.

## Project Layout

- `src/high_security_encryptor/`: implementation package
- `tests/`: unit and integration tests
- `examples/`: example JSON configs for each security mode
- `docs/`: format and batch-binding notes
- `.github/workflows/ci.yml`: Windows CI for Python 3.11, 3.12, and 3.13

## Current Status

- Streaming file encryption format is implemented.
- Legacy `GCM1` decryption compatibility is implemented.
- Batch binding, encrypted sidecars, and mixed file/folder workflows are implemented.
- Mixed batch decryption and folder auto-decryption are implemented.
- Runtime password providers and no-password-table flows are implemented.
- JSON config validation and report output are implemented.
- Third-stage hardening, modularization cleanup, and focused helper coverage are complete.
