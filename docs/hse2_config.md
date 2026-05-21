# Experimental HSE2 Config Files

HSE2 config commands are explicit experimental entry points for single-file HSE2
workflows. They do not replace the existing HSE1 batch config workflows.

## Commands

```bash
high-security-encryptor hse2-encrypt-config --config hse2_encrypt.json
high-security-encryptor hse2-decrypt-config --config hse2_decrypt.json
high-security-encryptor hse2-rewrap-config --config hse2_rewrap.json
```

## Encryption Config

```json
{
  "input": "plain.bin",
  "output": "cipher.hse2",
  "wrapper": {
    "type": "env",
    "name": "HSE2_WRAPPER"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576
}
```

Fields:

- `input`: plaintext input file.
- `output`: HSE2 output file.
- `wrapper`: password-provider spec used to wrap the HSE2 data key.
- `kdf_profile`: `compatible`, `hardened`, or `paranoid`; defaults to `hardened`.
- `chunk_size`: payload chunk size in bytes; defaults to 1048576.

## Decryption Config

```json
{
  "input": "cipher.hse2",
  "output": "restored.bin",
  "wrapper": {
    "type": "env",
    "name": "HSE2_WRAPPER"
  }
}
```

## Rewrap Config

```json
{
  "input": "cipher.hse2",
  "output": "rewrapped.hse2",
  "old_wrapper": {
    "type": "env",
    "name": "CURRENT_HSE2_WRAPPER"
  },
  "new_wrapper": {
    "type": "env",
    "name": "REPLACEMENT_HSE2_WRAPPER"
  },
  "new_kdf_profile": "hardened"
}
```

Rewrap replaces KDF/wrapped-DEK metadata and copies encrypted payload bytes
unchanged.

## Wrapper Provider Specs

HSE2 config files reuse the existing password-provider object format:

```json
{"type": "env", "name": "HSE2_WRAPPER"}
{"type": "file", "path": "C:/protected/hse2-wrapper.txt"}
{"type": "prompt", "prompt": "HSE2 wrapper: "}
```

Literal strings are accepted for compatibility with existing provider parsing,
but env, file, or prompt providers are preferred for operational use.

## Scope

Implemented:

- HSE2 encryption config object;
- HSE2 decryption config object;
- HSE2 rewrap config object;
- config-driven CLI commands;
- provider-backed wrapper resolution;
- tests for config parsing, validation, round trip, and rewrap.

Not implemented yet:

- multi-file HSE2 batch configs;
- GUI integration;
- migration from HSE1 to HSE2;
- making HSE2 the default format.
