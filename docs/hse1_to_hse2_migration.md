# Experimental HSE1 to HSE2 Migration

This workflow explicitly migrates existing HSE1 files into HSE2 containers. It
does not make HSE2 the default format and does not delete or modify the original
HSE1 files.

## Command

```bash
high-security-encryptor hse1-to-hse2 --config hse1_to_hse2.json
```

## Config

```json
{
  "items": [
    {
      "input": "old-file.hse",
      "output": "new-file.hse2"
    }
  ],
  "hse1_password": {
    "type": "env",
    "name": "HSE1_PASSWORD"
  },
  "hse2_wrapper": {
    "type": "env",
    "name": "HSE2_WRAPPER"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576,
  "continue_on_error": false
}
```

## Per-item Overrides

Batch-level `hse1_password` and `hse2_wrapper` apply to all items unless an item
supplies its own value.

```json
{
  "items": [
    {
      "input": "old-a.hse",
      "output": "new-a.hse2",
      "hse2_wrapper": {
        "type": "env",
        "name": "ITEM_A_HSE2_WRAPPER"
      }
    }
  ],
  "hse1_password": {
    "type": "env",
    "name": "HSE1_PASSWORD"
  },
  "hse2_wrapper": {
    "type": "env",
    "name": "DEFAULT_HSE2_WRAPPER"
  }
}
```

## Migration Flow

For each item, the helper:

1. resolves the HSE1 password provider;
2. resolves the HSE2 wrapper provider;
3. decrypts the HSE1 file into a temporary plaintext file;
4. encrypts that temporary plaintext file into an HSE2 container;
5. removes the temporary directory when the item finishes.

The original HSE1 input file is not deleted or modified.

## Security Notes

Temporary plaintext exists on disk during each item migration. The temporary
file is stored in an OS temporary directory and removed when the item completes,
but this is not equivalent to secure deletion on all filesystems or storage
hardware.

For highly sensitive migrations, run on a trusted local machine, avoid cloud-
synced temp directories, and consider full-disk encryption.

## Error Handling

- `continue_on_error: false` is the default. The migration stops after the first
  failed item and returns processed item results.
- `continue_on_error: true` continues processing later items and reports all
  item results.

## Scope

Implemented:

- list-based HSE1 to HSE2 migration;
- batch-level HSE1 password and HSE2 wrapper providers;
- item-level provider overrides;
- HSE2 KDF profile and chunk-size controls;
- continue-on-error behavior;
- tests for config parsing, round trip, provider overrides, and error behavior.

Not implemented yet:

- in-place migration;
- automatic deletion of original HSE1 files;
- secure overwrite guarantees for temporary plaintext;
- recursive directory discovery;
- GUI integration;
- migration of HSE1 batch manifests/templates as first-class artifacts.
