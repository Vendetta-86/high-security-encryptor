# Experimental HSE2 Batch Configs

HSE2 batch commands are explicit experimental entry points for multi-file HSE2
workflows. They do not replace the existing HSE1 `encrypt-batch` and
`decrypt-batch` commands.

## Commands

```bash
high-security-encryptor hse2-batch-encrypt --config hse2_batch_encrypt.json
high-security-encryptor hse2-batch-decrypt --config hse2_batch_decrypt.json
```

## Batch Encryption Config

```json
{
  "items": [
    {
      "input": "a.txt",
      "output": "a.txt.hse2"
    },
    {
      "input": "b.txt",
      "output": "b.txt.hse2"
    }
  ],
  "wrapper": {
    "type": "env",
    "name": "HSE2_WRAPPER"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576,
  "continue_on_error": false
}
```

## Batch Decryption Config

```json
{
  "items": [
    {
      "input": "a.txt.hse2",
      "output": "a.txt"
    },
    {
      "input": "b.txt.hse2",
      "output": "b.txt"
    }
  ],
  "wrapper": {
    "type": "env",
    "name": "HSE2_WRAPPER"
  },
  "continue_on_error": false
}
```

## Per-item Wrapper Override

A batch-level `wrapper` applies to all items unless an item supplies its own
`wrapper`.

```json
{
  "items": [
    {
      "input": "sensitive-a.txt",
      "output": "sensitive-a.txt.hse2",
      "wrapper": {
        "type": "env",
        "name": "HSE2_ITEM_A_WRAPPER"
      }
    }
  ],
  "wrapper": {
    "type": "env",
    "name": "HSE2_DEFAULT_WRAPPER"
  }
}
```

## Error Handling

- `continue_on_error: false` is the default. The batch stops after the first
  failed item and reports the processed item results.
- `continue_on_error: true` continues processing later items and reports all
  item results.

The JSON summary includes:

- total processed items;
- succeeded count;
- failed count;
- per-item input, output, status, and error string.

## Scope

Implemented:

- list-based HSE2 batch encryption;
- list-based HSE2 batch decryption;
- batch-level wrapper provider;
- per-item wrapper override;
- KDF/chunk-size controls for batch encryption;
- continue-on-error behavior;
- tests for round trips and error behavior.

Not implemented yet:

- recursive directories;
- bundle/package output;
- manifest/template sidecars;
- HSE2 batch rewrap;
- migration from HSE1 batch artifacts;
- GUI integration.
