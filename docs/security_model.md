# Security Model

This document describes what High Security Encryptor is designed to protect, what it does not protect, and how the batch sidecar files should be handled.

## Protection Goals

- Protect file contents at rest when encrypted files are copied, backed up, or stored on untrusted media.
- Detect ciphertext tampering through authenticated encryption.
- Bind batch metadata sidecars to the intended batch so a password table, template, or manifest from another batch is rejected.
- Support workflows where password tables are not stored long term and passwords are supplied at runtime.
- Preserve compatibility with legacy `GCM1` decryption for existing encrypted files.

## Non-Goals

- This tool does not protect plaintext files before encryption or after decryption.
- This tool does not hide file sizes, output file names, batch entry counts, or folder structure inside decrypted archives.
- This tool does not provide multi-user access control, remote key management, or hardware-backed key storage.
- This tool does not make weak passwords safe.
- This tool does not protect secrets exposed through environment variables, command output, shell history, terminal logs, process lists, backups, or malware on the host.
- This tool does not erase deleted plaintext or password-table files from storage devices.

## File Encryption

Encrypted file payloads use authenticated encryption. Decryption fails if chunk authentication, trailer authentication, chunk counts, plaintext size, or plaintext digest validation fails.

Operationally, any integrity failure should be treated as one of these conditions:

- wrong password
- corrupted encrypted file
- tampered encrypted file
- mismatched sidecar set
- bug or unsupported format

Do not retry integrity failures by changing sidecars at random. Rebuild the batch context from known-good artifacts.

## Metadata Password

The metadata password protects encrypted sidecar artifacts such as manifests, password tables, and templates.

The metadata password is separate from per-file encryption passwords. Losing the metadata password may prevent recovery of sidecar contents. Exposing it may reveal metadata and, in compatible modes, password-table contents.

Use a metadata password with the same care as the file passwords.

## Sidecar Artifacts

### Manifest

The manifest records encrypted batch entries and binding data. It is required for batch decryption and entry-set validation.

Sensitivity:

- Reveals encrypted entry names and batch shape after metadata decryption.
- Does not contain plaintext file passwords.
- Should be stored with the encrypted batch.

### Template

The template maps source names to encrypted names and supports runtime password plans.

Sensitivity:

- Reveals source-name relationships after metadata decryption.
- Does not contain passwords.
- Required for no-password-table recovery flows.

### Password Table

The password table stores per-entry passwords encrypted with the metadata password.

Sensitivity:

- Highly sensitive.
- If the metadata password is compromised, stored file passwords are compromised.
- Should be avoided for high-value long-term storage when runtime password providers are practical.

## Security Modes

### compatible

`compatible` writes top-level and internal password-table sidecars.

Use when:

- maximum compatibility is more important than minimizing stored password material
- operators need straightforward recovery from a complete sidecar set

Risk:

- password tables become long-term secret-bearing artifacts

### hardened

`hardened` omits the top-level password table but keeps internal folder password tables.

Use when:

- top-level passwords should not be stored
- folder-internal recovery still needs compatibility

Risk:

- folder-internal password tables can still contain secret material

### no-password-tables

`no-password-tables` omits all password tables.

Use when:

- operators can supply passwords through runtime providers
- long-term stored password material should be minimized

Risk:

- recovery depends on preserving manifests/templates and retaining access to external password sources
- misconfigured providers can make decryption impossible until fixed

## Runtime Password Providers

Supported providers are `literal`, `env`, `prompt`, `file`, and `command`.

Provider risk:

- `literal`: convenient but stores the secret directly in config files
- `env`: avoids config-file secrets but can leak through process environments, logs, shells, and CI settings
- `prompt`: good for interactive use but unsuitable for unattended jobs
- `file`: shifts protection to filesystem ACLs and backup policy
- `command`: shifts protection to the invoked program, its arguments, output handling, and host security

The `command` provider uses an explicit `argv` array and does not invoke a shell. This reduces shell-injection risk, but the command itself is still trusted code.

## Batch Binding

Batch binding checks that sidecars agree on:

- `batch_id`
- expected file count
- encrypted entry-name fingerprint

This protects against accidental or malicious sidecar substitution across batches.

It does not prove that a human selected the intended batch, and it does not protect against a compromise where the attacker can replace every encrypted file and every sidecar with a self-consistent malicious set.

## Recommended Baseline

For high-value long-term storage:

1. Use `no-password-tables`.
2. Store encrypted files, manifest, and template together.
3. Store password sources separately from encrypted data.
4. Protect the metadata password separately from file passwords.
5. Test recovery with a temporary restore before relying on a backup process.
6. Keep old sidecar sets with their matching encrypted files; do not mix batches.
