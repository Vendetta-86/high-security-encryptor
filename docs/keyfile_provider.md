# Keyfile Password Source Provider

The `keyfile` provider reads a local binary file and converts it into stable
wrapper material for workflows that use password-source provider specs.

This is primarily useful for HSE2 wrapper fields where operators want a local
file-backed wrapper instead of an environment variable, prompt, text file, or
command.

## Provider Spec

```json
{
  "type": "keyfile",
  "path": "C:/protected/wrapper.key"
}
```

The provider can be used anywhere the existing password-source object format is
accepted, including HSE2 config files:

```json
{
  "input": "plain.bin",
  "output": "cipher.hse2",
  "wrapper": {
    "type": "keyfile",
    "path": "C:/protected/wrapper.key"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576
}
```

## Behavior

The provider:

1. reads the file as binary bytes;
2. requires at least 16 bytes;
3. rejects files larger than 1 MiB;
4. encodes the bytes into version-prefixed stable wrapper material;
5. passes that wrapper material into the existing KDF/wrapping flow.

The keyfile bytes are not printed in CLI summaries.

## Creating a Keyfile

Use a cryptographically secure random source. For example, with Python:

```bash
python -c "import secrets, pathlib; pathlib.Path('wrapper.key').write_bytes(secrets.token_bytes(32))"
```

Keep the keyfile private. Anyone with the HSE2 file and the matching keyfile can
attempt decryption.

## Scope

Implemented:

- `keyfile` password-source provider;
- binary keyfile reading in the default CLI resolver;
- size limits;
- HSE2 config compatibility;
- tests for provider behavior and HSE2 encrypt/validate/decrypt round trip.

Not implemented yet:

- keyfile generation command;
- keyfile rotation helper;
- OS keychain/DPAPI/TPM-backed keyfile protection;
- GUI keyfile selection.
