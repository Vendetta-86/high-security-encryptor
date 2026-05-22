# HSE2 Wrapper Provider Matrix

HSE2 wrapper fields accept the same password-source provider object format used
by the rest of the CLI. This document summarizes the supported provider options
for HSE2 encrypt, decrypt, validate, rewrap, batch, migration, and keyfile
rotation workflows.

## Supported Providers

| Provider | Example | Best fit | Portability |
|---|---|---|---|
| `literal` | `{ "type": "literal", "value": "..." }` | tests and throwaway local experiments | portable but unsafe in committed config |
| `env` | `{ "type": "env", "name": "HSE2_WRAPPER" }` | CI and shell-driven automation | portable if environment is recreated |
| `file` | `{ "type": "file", "path": "wrapper.txt" }` | text-based local secret files | portable |
| `keyfile` | `{ "type": "keyfile", "path": "wrapper.key" }` | binary file-backed wrapper material | portable if copied securely |
| `dpapi` | `{ "type": "dpapi", "path": "wrapper.dpapi" }` | Windows local user/machine-bound storage | not generally portable |
| `command` | `{ "type": "command", "argv": ["tool", "print-wrapper"] }` | external secret managers | depends on the command and environment |
| `prompt` | `{ "type": "prompt", "prompt": "Wrapper: " }` | interactive local use | not automation-friendly |

## Recommended Usage

For local HSE2 use on Windows, prefer:

```json
{
  "type": "dpapi",
  "path": "wrapper.dpapi"
}
```

For portable offline archives, prefer:

```json
{
  "type": "keyfile",
  "path": "wrapper.key"
}
```

For CI, prefer:

```json
{
  "type": "env",
  "name": "HSE2_WRAPPER"
}
```

Avoid `literal` in committed config files.

## HSE2 Encrypt Config Examples

### Environment Variable

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

### Binary Keyfile

```json
{
  "input": "plain.bin",
  "output": "cipher.hse2",
  "wrapper": {
    "type": "keyfile",
    "path": "wrapper.key"
  },
  "kdf_profile": "hardened",
  "chunk_size": 1048576
}
```

### Windows DPAPI Blob

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

## Creating Wrapper Material

Create a keyfile:

```bash
high-security-encryptor generate-keyfile --output wrapper.key
```

Protect it with Windows DPAPI:

```bash
high-security-encryptor dpapi-protect --input wrapper.key --output wrapper.dpapi
```

## Validation

Validate an HSE2 file without writing plaintext:

```bash
high-security-encryptor hse2-validate --config hse2_validate.json --summary-only --exit-code-on-failure
```

## Rotation

Rotate between two keyfiles:

```bash
high-security-encryptor hse2-rotate-keyfile --config hse2_rotate_keyfile.json
```

For non-keyfile providers, use the general HSE2 rewrap commands.

## Security Notes

- Wrapper provider config is not itself a complete security boundary.
- Protect wrapper files with OS filesystem permissions.
- Do not commit raw secrets, keyfiles, DPAPI blobs, or literal wrapper values.
- DPAPI blobs are tied to the protecting Windows user or machine scope.
- Keep old keyfiles until all rotated files have been validated and backed up.
