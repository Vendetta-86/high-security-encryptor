# Operational Guidance

This document gives practical guidance for running High Security Encryptor in repeatable local workflows.

## Recommended Mode

Use `no-password-tables` for high-value long-term storage when operators can reliably provide passwords at runtime.

Use `hardened` when top-level password tables must be avoided but folder-internal compatibility is still needed.

Use `compatible` only when password-table sidecars are acceptable and operational simplicity is more important than minimizing stored secret material.

## Artifact Handling

Keep these artifacts together:

- encrypted `.hse` files
- encrypted folder packages, usually `.zip.hse`
- `batch_manifest.hsm`
- `batch_template.hsm`

If password tables are intentionally generated, treat these as secret-bearing files:

- top-level `batch_password_table.hsm`
- folder-internal `_hse_sidecars/batch_password_table.hsm`

Do not mix sidecars between batches. Batch binding catches many mismatches, but operators should still preserve batch directories as immutable units.

The `_hse_sidecars` folder name is reserved inside encrypted folder packages. Do not use that name inside source folders that will be packaged.

## Password Handling

Prefer runtime password providers over storing secrets in config files.

Recommended provider choices:

- `prompt` for manual recovery and high-sensitivity one-off operations
- `env` for controlled automation where the runtime environment is already protected
- `file` for local automation when filesystem permissions and backup policy are well understood
- `command` when a dedicated local secret helper is available

Avoid `literal` in shared configs or committed files.

The GUI defaults to `no-password-tables` for generated encryption configs and writes password fields as `env` providers. When you choose "generate and run", the GUI supplies those environment variables only for that run. If you save a generated config and run it later, set the referenced environment variables first or edit the config to use another provider.

CLI encryption configs that omit `security_mode` also default to `no-password-tables`, unless they explicitly request password-table output. Older decrypt configs that omit `security_mode` and include `password_table_path` continue to load as compatible configs.

## Temporary Files

Folder encryption streams ZIP data directly into the encrypted output, so it does not create a temporary plaintext ZIP. Folder decryption still creates a temporary plaintext ZIP long enough to validate and extract it.

Set `HSE_TEMP_DIR` to a local, access-controlled directory when the default system temp location is not acceptable:

```bash
set HSE_TEMP_DIR=D:\hse-temp
```

The tool creates per-run private subdirectories below that path and removes them after use. It does not provide forensic secure deletion on SSDs or journaling filesystems, so use encrypted local storage for temporary directories when that matters.

## Example No-Password-Table Flow

Create a no-password-table encryption config:

```bash
high-security-encryptor init-example --mode no-password-tables --kind encrypt --output encrypt.json
```

Validate it:

```bash
high-security-encryptor validate-config --kind encrypt --config encrypt.json --report
```

Encrypt:

```bash
high-security-encryptor encrypt-batch --config encrypt.json
```

Create a matching decrypt config:

```bash
high-security-encryptor init-example --mode no-password-tables --kind decrypt --output decrypt.json
```

Validate strictly:

```bash
high-security-encryptor validate-config --kind decrypt --config decrypt.json --strict --report --exit-code-on-issues
```

Decrypt:

```bash
high-security-encryptor decrypt-batch --config decrypt.json
```

## Backup Guidance

Back up encrypted data and non-secret metadata together:

- encrypted files
- manifest
- template
- docs or runbooks describing which password providers are needed

Back up secrets separately:

- metadata password
- file passwords
- provider backing stores

Test restore periodically by decrypting a small representative batch into a temporary directory.

## Rotation Guidance

To rotate file passwords, decrypt and re-encrypt the affected files or batches with new passwords. Keep the old batch until the new batch has been validated and restore-tested.

To rotate the metadata password, regenerate sidecars by re-encrypting the batch. Do not edit encrypted sidecar files manually.

To rotate provider names or locations, update the decrypt config and run:

```bash
high-security-encryptor validate-config --kind decrypt --config decrypt.json --strict --report
```

## Failure Handling

### Config Failures

Exit code `3` indicates a command input or config problem. Check:

- config path
- JSON syntax
- required fields
- security mode compatibility
- missing runtime password mappings

Normal CLI errors redact absolute paths. Re-run with `--debug` only when the terminal output is trusted and you need exact paths or tracebacks.

### Password Provider Failures

Exit code `4` indicates a provider could not resolve a password. Check:

- environment variable names
- secret file paths and permissions
- command provider executable path and exit code
- empty provider output

Normal CLI errors redact environment variable names. Check the referenced config file when you need the exact provider name.

### Integrity Failures

Exit code `5` indicates authentication, integrity, or entry-set validation failed. Check:

- wrong password
- mismatched manifest/template/password table
- missing or extra encrypted files
- corrupted encrypted files
- folder packages modified after encryption
- malformed or oversized sidecar metadata

Do not overwrite original encrypted files while investigating integrity failures.

## CI and Automation

For automation, use:

```bash
high-security-encryptor validate-config --kind encrypt --config encrypt.json --report --exit-code-on-issues --warnings-as-errors
```

For decrypt configs in `hardened` or `no-password-tables` mode, prefer `--strict` so accidental password-table use or non-template runtime mappings are caught early.

For repository automation, run:

```bash
pre-commit run --all-files
python -m pip_audit . --progress-spinner off
```

The pre-commit configuration uses `detect-secrets` with `.secrets.baseline`; update the baseline only after reviewing any newly detected values.
