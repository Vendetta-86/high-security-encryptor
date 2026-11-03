# Windows DPAPI Provider

The `dpapi` provider is a Windows-only password-source provider. It reads a
local DPAPI-protected blob file and converts the unprotected bytes into stable
wrapper material.

This is intended for local Windows workflows where wrapper material should be
bound to the current Windows user or, optionally, the local machine.
The standalone HSE2 GUI exposes the protect action and can run JSON encrypt/decrypt
configs that use this provider; a guided exercise is in
`docs/beginner/hse2-dpapi-keyfile-practice.md`.

## Protect a Local Keyfile

First create a normal keyfile:

```bash
high-security-encryptor generate-keyfile --output wrapper.key
```

Then protect it with Windows DPAPI:

```bash
high-security-encryptor dpapi-protect \
  --input wrapper.key \
  --output wrapper.dpapi
```

The default scope is `current_user`. This means the blob is intended to be
unprotected by the same Windows user profile.

You can request local-machine scope:

```bash
high-security-encryptor dpapi-protect \
  --input wrapper.key \
  --output wrapper.dpapi \
  --scope local_machine
```

The command refuses to overwrite an existing blob unless `--force` is provided.

## Provider Spec

```json
{
  "type": "dpapi",
  "path": "wrapper.dpapi"
}
```

Example HSE2 encryption config:

```json
{
  "input": "plain.bin",
  "output": "cipher.hse2",
  "wrapper": {
    "type": "dpapi",
    "path": "wrapper.dpapi"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576
}
```

## Behavior

The provider:

1. reads the DPAPI blob file;
2. verifies the `hse-dpapi-v1:` prefix;
3. base64-decodes the protected blob;
4. calls Windows `CryptUnprotectData`;
5. validates the unprotected material size;
6. passes version-prefixed wrapper material into the existing HSE2 wrapping flow.

The unprotected bytes are not printed in CLI summaries.

## Scope and Portability

- `current_user`: bound to the Windows user profile.
- `local_machine`: bound to the local Windows machine.

DPAPI blobs are not portable like ordinary keyfiles. A blob protected for one
user or machine may not be usable elsewhere.

## Scope

Implemented:

- Windows-only DPAPI protect/unprotect helper;
- `dpapi-protect` command;
- standalone HSE2 GUI action for protecting a keyfile;
- `dpapi` password-source provider;
- standalone HSE2 GUI actions for running JSON encryption/decryption configs that use the provider;
- current-user and local-machine scope options;
- default overwrite refusal with `--force` override;
- Windows round-trip tests and non-Windows unavailable-path tests.

Not implemented yet:

- DPAPI entropy parameter support;
- an in-GUI editor for DPAPI provider JSON fields;
- automatic deletion of the original unprotected keyfile;
- migration helper from keyfile provider to DPAPI provider.
