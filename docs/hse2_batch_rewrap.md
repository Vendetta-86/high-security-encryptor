# Experimental HSE2 Batch Rewrap

HSE2 batch rewrap is an explicit experimental workflow for replacing wrapper
metadata across multiple HSE2 files. It does not replace or modify existing HSE1
workflows.

## Command

```bash
high-security-encryptor hse2-batch-rewrap --config hse2_batch_rewrap.json
```

## Config

```json
{
  "items": [
    {
      "input": "a.hse2",
      "output": "a.rewrapped.hse2"
    },
    {
      "input": "b.hse2",
      "output": "b.rewrapped.hse2"
    }
  ],
  "old_wrapper": {
    "type": "env",
    "name": "CURRENT_HSE2_WRAPPER"
  },
  "new_wrapper": {
    "type": "env",
    "name": "REPLACEMENT_HSE2_WRAPPER"
  },
  "new_kdf_profile": "hardened",
  "continue_on_error": false
}
```

## Per-item Wrapper Overrides

Batch-level `old_wrapper` and `new_wrapper` apply to all items unless an item
supplies its own override.

```json
{
  "items": [
    {
      "input": "a.hse2",
      "output": "a.rewrapped.hse2",
      "new_wrapper": {
        "type": "env",
        "name": "ITEM_A_REPLACEMENT_WRAPPER"
      }
    }
  ],
  "old_wrapper": {
    "type": "env",
    "name": "CURRENT_HSE2_WRAPPER"
  },
  "new_wrapper": {
    "type": "env",
    "name": "DEFAULT_REPLACEMENT_WRAPPER"
  }
}
```

## Safety Invariant

Batch rewrap uses the same single-file HSE2 rewrap helper. For each item it:

1. authenticates the existing wrapper;
2. builds replacement wrapper metadata;
3. verifies immutable payload AAD remains unchanged;
4. writes a new header and copies encrypted payload bytes unchanged.

If a replacement header would change the payload authentication context, the item
fails.

## Error Handling

- `continue_on_error: false` is the default. The batch stops after the first
  failed item and returns processed item results.
- `continue_on_error: true` continues processing later items and reports all
  item results.

## Scope

Implemented:

- list-based HSE2 batch rewrap;
- batch-level current/replacement wrapper providers;
- item-level wrapper overrides;
- replacement KDF profile;
- continue-on-error behavior;
- per-item result summaries;
- tests for round trip, overrides, and error behavior.

Not implemented yet:

- in-place rewrap;
- recursive directory discovery;
- manifest/template sidecars;
- GUI integration;
- HSE1 to HSE2 migration.
