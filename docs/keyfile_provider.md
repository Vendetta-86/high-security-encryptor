# Keyfile Password Source Provider

The `keyfile` provider reads a local binary file and converts it into stable
wrapper material for workflows that use password-source provider specs.

This is primarily useful for HSE2 wrapper fields where operators want a local
file-backed wrapper instead of an environment variable, prompt, text file, or
command.

## Generate a Keyfile

Use the built-in generator to create a random keyfile:

```bash
high-security-encryptor generate-keyfile --output wrapper.key
```

The default size is 32 bytes. You can choose another size within the supported
range:

```bash
high-security-encryptor generate-keyfile --output wrapper.key --size 64
```

The command refuses to overwrite an existing file unless `--force` is provided:

```bash
high-security-encryptor generate-keyfile --output wrapper.key --force
```

The command summary reports only the output path, size, and whether an existing
file was overwritten. It does not print the generated random bytes.

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

## Creating a Keyfile Manually

The built-in generator is preferred. If you need a manual method, use a
cryptographically secure random source. For example, with Python:

```bash
python -c "import secrets, pathlib; pathlib.Path('wrapper.key').write_bytes(secrets.token_bytes(32))"
```

Keep the keyfile private. Anyone with the HSE2 file and the matching keyfile can
attempt decryption.

## Scope

Implemented:

- `generate-keyfile` command;
- random keyfile generation with `secrets.token_bytes`;
- default 32-byte keyfiles;
- explicit size control;
- default refusal to overwrite existing keyfiles;
- explicit `--force` overwrite;
- `keyfile` password-source provider;
- binary keyfile reading in the default CLI resolver;
- size limits;
- HSE2 config compatibility;
- tests for generation, provider behavior, and HSE2 encrypt/validate/decrypt round trip.

Not implemented yet:

- keyfile rotation helper;
- OS keychain/DPAPI/TPM-backed keyfile protection;
- GUI keyfile selection.
