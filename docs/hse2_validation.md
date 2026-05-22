# Experimental HSE2 Validation Reports

HSE2 validation reports are explicit read-only workflows for checking HSE2
containers without writing plaintext output.

## Command

```bash
high-security-encryptor hse2-validate --config hse2_validate.json
```

## Config

```json
{
  "items": [
    {
      "input": "a.hse2"
    },
    {
      "input": "b.hse2"
    }
  ],
  "wrapper": {
    "type": "env",
    "name": "HSE2_WRAPPER"
  },
  "continue_on_error": true
}
```

## Per-item Wrapper Override

A batch-level `wrapper` applies to every item unless an item supplies its own
wrapper provider.

```json
{
  "items": [
    {
      "input": "a.hse2",
      "wrapper": {
        "type": "env",
        "name": "ITEM_A_HSE2_WRAPPER"
      }
    }
  ],
  "wrapper": {
    "type": "env",
    "name": "DEFAULT_HSE2_WRAPPER"
  }
}
```

## What Is Checked

For each item, the validator:

1. reads and validates the HSE2 header;
2. derives the wrapping key from the configured wrapper provider;
3. authenticates and unwraps the encrypted data key;
4. verifies each payload chunk's AES-GCM tag;
5. verifies the trailer tag;
6. checks chunk count, plaintext size, and plaintext SHA-256 digest.

The validator does not write plaintext output.

## Report Fields

Each item reports:

- `ok`;
- `header_ok`;
- `payload_ok`;
- file size;
- HSE2 version;
- content algorithm;
- KDF profile;
- chunk size;
- chunk count;
- plaintext size;
- plaintext SHA-256 digest;
- error string when validation fails.

## Error Handling

- `continue_on_error: true` is the default. All items are checked and reported.
- `continue_on_error: false` stops after the first failed item.

## Scope

Implemented:

- read-only single-file HSE2 validation helper;
- batch validation config;
- `hse2-validate --config ...` command;
- wrapper providers and per-item overrides;
- JSON summary with aggregate success/failure counts;
- tests for success, wrapper failure, no plaintext output, and error behavior.

Not implemented yet:

- text report output;
- writing reports to files;
- integration with HSE1 validation reports;
- GUI integration.
