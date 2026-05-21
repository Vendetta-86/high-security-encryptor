# Experimental HSE2 CLI Commands

HSE2 CLI commands are explicit experimental entry points. They do not replace the
existing HSE1 batch encryption/decryption workflows.

## Wrapper Input Sources

Each HSE2 command requires exactly one wrapper input source for each wrapper
value it needs.

Supported sources:

- literal argument: `--secret VALUE`, `--old-secret VALUE`, `--new-secret VALUE`;
- environment variable: `--secret-env NAME`, `--old-secret-env NAME`, `--new-secret-env NAME`;
- UTF-8 file: `--secret-file PATH`, `--old-secret-file PATH`, `--new-secret-file PATH`;
- interactive prompt: `--secret-prompt`, `--old-secret-prompt`, `--new-secret-prompt`.

Prefer env, file, or prompt sources. Literal arguments are kept for tests and
quick experiments, but command-line arguments may be visible to local process
inspection tools and shell history.

## Commands

### Encrypt one file

```bash
high-security-encryptor hse2-encrypt \
  --input plain.bin \
  --output cipher.hse2 \
  --secret-env HSE2_WRAPPER \
  --kdf-profile hardened
```

Optional arguments:

- `--kdf-profile`: `compatible`, `hardened`, or `paranoid`; defaults to `hardened`.
- `--chunk-size`: payload chunk size in bytes; defaults to 1048576.

### Decrypt one file

```bash
high-security-encryptor hse2-decrypt \
  --input cipher.hse2 \
  --output restored.bin \
  --secret-env HSE2_WRAPPER
```

### Rewrap one file

```bash
high-security-encryptor hse2-rewrap \
  --input cipher.hse2 \
  --output rewrapped.hse2 \
  --old-secret-env CURRENT_HSE2_WRAPPER \
  --new-secret-env REPLACEMENT_HSE2_WRAPPER \
  --new-kdf-profile hardened
```

Rewrap replaces KDF/wrapped-DEK metadata and copies payload bytes unchanged.

## Security Notes

The provider options reduce accidental exposure compared with literal command-line
arguments. They do not remove the need for host security, access control, careful
shell history handling, and protected storage for wrapper files or environment
variables.

## Scope

Implemented:

- explicit single-file HSE2 encryption command;
- explicit single-file HSE2 decryption command;
- explicit single-file HSE2 rewrap command;
- env/file/prompt/literal wrapper input sources;
- JSON summaries that report wrapper source type without echoing the value;
- CLI tests for round trip, provider sources, rewrap, and help visibility.

Not implemented yet:

- batch HSE2 configs;
- GUI integration;
- migration from HSE1 to HSE2;
- making HSE2 the default format.
