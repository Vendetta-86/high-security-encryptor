# Experimental HSE2 CLI Commands

HSE2 CLI commands are explicit experimental entry points. They do not replace the
existing HSE1 batch encryption/decryption workflows.

## Commands

### Encrypt one file

```bash
high-security-encryptor hse2-encrypt \
  --input plain.bin \
  --output cipher.hse2 \
  --secret <WRAPPER_SECRET> \
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
  --secret <WRAPPER_SECRET>
```

### Rewrap one file

```bash
high-security-encryptor hse2-rewrap \
  --input cipher.hse2 \
  --output rewrapped.hse2 \
  --old-secret <CURRENT_WRAPPER_SECRET> \
  --new-secret <REPLACEMENT_WRAPPER_SECRET> \
  --new-kdf-profile hardened
```

Rewrap replaces KDF/wrapped-DEK metadata and copies payload bytes unchanged.

## Security Notes

These commands currently accept wrapper material as command-line arguments for
experimental testing. Command-line arguments may be visible to local process
inspection tools and shell history. Production HSE2 CLI flows should add
environment, prompt, or file-based providers before being promoted out of
experimental status.

## Scope

Implemented:

- explicit single-file HSE2 encryption command;
- explicit single-file HSE2 decryption command;
- explicit single-file HSE2 rewrap command;
- JSON summaries;
- CLI tests for round trip, rewrap, and help visibility.

Not implemented yet:

- batch HSE2 configs;
- GUI integration;
- prompt/env/file providers for HSE2 commands;
- migration from HSE1 to HSE2;
- making HSE2 the default format.
