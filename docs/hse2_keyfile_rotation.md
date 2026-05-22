# Experimental HSE2 Keyfile Rotation

HSE2 keyfile rotation is a convenience wrapper around the existing HSE2 rewrap
workflow. It rotates HSE2 files from one keyfile-backed wrapper to another
without changing the original input file or deleting any keyfile.

## Command

```bash
high-security-encryptor hse2-rotate-keyfile --config hse2_rotate_keyfile.json
```

## Config

```json
{
  "items": [
    {
      "input": "a.hse2",
      "output": "a.rotated.hse2"
    }
  ],
  "old_keyfile": "old-wrapper.key",
  "new_keyfile": "new-wrapper.key",
  "new_kdf_profile": "hardened",
  "continue_on_error": false
}
```

## Behavior

For each item, the command:

1. reads the old keyfile through the `keyfile` provider;
2. reads the new keyfile through the `keyfile` provider;
3. uses the existing HSE2 rewrap flow to authenticate the old wrapper and write a
   new HSE2 file using the new wrapper;
4. leaves the original HSE2 file unchanged;
5. leaves both keyfiles unchanged.

## Safety Boundaries

The command does not:

- perform in-place replacement;
- delete the original HSE2 file;
- delete the old keyfile;
- print keyfile bytes;
- change default HSE2 behavior.

## Error Handling

- `continue_on_error: false` is the default. The command stops after the first
  failed item and returns processed item results.
- `continue_on_error: true` continues processing later items and reports all
  item results.

## Scope

Implemented:

- config-only `hse2-rotate-keyfile` command;
- list-based keyfile rotation;
- replacement KDF profile;
- continue-on-error behavior;
- per-item JSON summary;
- tests for parsing, round trip, and error behavior.

Not implemented yet:

- in-place replacement;
- automatic backup naming;
- keyfile generation as part of rotation;
- keyfile deletion or archival;
- GUI integration.
