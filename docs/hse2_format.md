# HSE2 Container Format

This document freezes the initial HSE2 container direction for offline-hardening work. It is intentionally conservative: HSE2 is a file-level encrypted container format, not a disk-encryption or hidden-volume system.

## Goals

- Provide a self-describing encrypted container format.
- Support offline brute-force resistance through authenticated KDF metadata, strong Argon2id profiles, random data keys, and external wrapper material.
- Support multiple unlock wrappers for password, keyfile, password+keyfile, and Windows DPAPI workflows.
- Encrypt payload metadata by default for hardened and paranoid workflows.
- Support explicit header backup and explicit access destruction workflows.
- Preserve streaming encryption/decryption for large files.

## Non-goals

- HSE2 does not provide virtual disk mounting.
- HSE2 does not replace VeraCrypt, BitLocker, LUKS, or platform disk encryption.
- HSE2 does not claim full plausible deniability or hidden-volume security.
- HSE2 does not promise secure deletion of plaintext, temporary files, SSD blocks, filesystem journals, OS caches, or backups.
- HSE2 must not provide a default automatic nuke password that silently destroys access during normal unlock.

## Threat model

HSE2 protects encrypted files and encrypted metadata at rest. It is designed to raise the cost of offline attacks when an attacker obtains copied ciphertext.

HSE2 assumes that if an attacker has all ciphertext, all wrappers, all keyfiles, and a weak password, offline guessing remains possible. Offline resistance must therefore combine:

- strong user passwords;
- Argon2id hardened or paranoid profiles;
- random DEK/MEK material;
- keyfiles or other external pepper material not stored beside the ciphertext;
- DPAPI or platform-bound wrappers for local convenience only;
- encrypted metadata and minimized plaintext header information.

## Container layout

The initial HSE2 container is a single file with this logical layout:

```text
HSE2 Container
├── fixed preamble
├── authenticated header
├── encrypted manifest
├── encrypted payload chunks
└── footer
```

The physical layout should remain streaming-friendly. Implementations may write the header before payload when sizes are known, or reserve/update the header atomically when needed. Header update operations must use write-to-temp-and-rename semantics where possible.

## Fixed preamble

The preamble is the minimal unencrypted data needed to identify and parse the container.

Required fields:

| Field | Purpose |
|---|---|
| `magic` | Constant `HSE2` marker. |
| `format_version` | Integer format version. Initial value: `2`. |
| `header_length` | Length of the serialized authenticated header. |
| `header_encoding` | Initial value: `canonical-json`. |

The preamble must not contain passwords, key material, file names, source paths, or KDF salts.

## Authenticated header

The authenticated header is serialized deterministically. The initial encoding is canonical JSON unless implementation constraints require a stricter binary encoding later.

Recommended top-level shape:

```json
{
  "format": "HSE2",
  "format_version": 2,
  "created_utc": "2026-05-25T00:00:00Z",
  "cipher_suite": {
    "payload_cipher": "AES-256-GCM",
    "manifest_cipher": "AES-256-GCM",
    "wrap_cipher": "AES-256-GCM",
    "chunk_size": 1048576
  },
  "manifest_policy": {
    "encrypted": true,
    "store_original_paths": false,
    "filename_policy": "encrypted"
  },
  "payload_layout": {
    "chunk_count": 0,
    "payload_offset": 0,
    "footer_offset": 0
  },
  "wrappers": [],
  "header_auth": {
    "algorithm": "HMAC-SHA256",
    "tag": "base64..."
  }
}
```

The header authentication tag must cover all security-critical header fields, including KDF parameters, wrapper metadata, cipher selections, manifest policy, payload layout, and nonce/salt fields that influence decryption.

## Key model

HSE2 uses random content keys. User passwords must not directly encrypt large payloads.

Required keys:

| Key | Size | Purpose |
|---|---:|---|
| `DEK` | 32 bytes | Encrypts payload chunks. |
| `MEK` | 32 bytes | Encrypts the manifest. |
| `KEK` | 32 bytes | Derived or loaded by a wrapper provider, then used to wrap DEK/MEK. |

Encryption flow:

```text
random DEK + random MEK
        ↓
DEK encrypts payload chunks
MEK encrypts manifest
        ↓
password/keyfile/DPAPI provider yields KEK
        ↓
KEK wraps DEK and MEK inside one or more wrappers
```

Password changes, keyfile rotation, and DPAPI additions should rewrap DEK/MEK without rewriting payload bytes.

## Wrapper records

Each wrapper record describes one unlock method. It must contain enough authenticated metadata to validate provider type, KDF parameters, salts, nonces, and wrapped key blobs.

Recommended shape:

```json
{
  "id": "password-1",
  "type": "password",
  "label": "main password",
  "created_utc": "2026-05-25T00:00:00Z",
  "kdf": {
    "algorithm": "argon2id",
    "profile": "hardened",
    "time_cost": 3,
    "memory_cost_kib": 262144,
    "parallelism": 4,
    "hash_len": 32,
    "salt": "base64..."
  },
  "wrap_cipher": "AES-256-GCM",
  "nonce": "base64...",
  "wrapped_keys": {
    "dek": "base64...",
    "mek": "base64..."
  },
  "auth_tag": "base64..."
}
```

Supported initial wrapper types:

| Type | Required for initial implementation | Notes |
|---|---:|---|
| `password` | yes | Password-derived KEK via Argon2id. |
| `keyfile` | yes | Binary keyfile material derives or directly supplies KEK material. |
| `password_keyfile` | yes | Combines password and keyfile before deriving KEK. Recommended for offline archives. |
| `dpapi` | yes on Windows | Local convenience wrapper. Must not be the only long-term recovery path. |

Future wrapper types may include `recovery`, `command`, `prompt`, `tpm`, and `duress`, but they are out of scope for the initial format freeze.

## KDF profiles

HSE2 serializes KDF parameters in each relevant wrapper. Profiles are names plus explicit parameter values.

Initial Argon2id profiles:

| Profile | Memory | `memory_cost_kib` | `time_cost` | `parallelism` | Purpose |
|---|---:|---:|---:|---:|---|
| `compatible` | 64 MiB | 65536 | 3 | 4 | Compatibility and low-memory use. |
| `hardened` | 256 MiB | 262144 | 3 | 4 | Default high-security mode. |
| `paranoid` | 1 GiB | 1048576 | 4 | 4 | High-value low-frequency archives. |

`hardened` should be the default for new HSE2 encryption. `paranoid` should strongly recommend, or eventually require, `password_keyfile` rather than password-only unlocking.

## Manifest

The manifest records payload metadata. In hardened and paranoid workflows, it must be encrypted with MEK.

Manifest may include:

- relative file names;
- file sizes;
- file content hashes;
- directory structure for bundled folder archives;
- per-entry payload offsets;
- chunk counts;
- modification timestamps when explicitly allowed.

Manifest must not store by default:

- absolute source paths;
- Windows account names;
- drive letters;
- original working directory;
- plaintext passwords;
- keyfile paths except as non-secret local hints when explicitly requested.

## Header backup

HSE2 must support exporting and restoring a header backup.

Header backup may contain:

- preamble;
- authenticated header;
- wrapper records;
- encrypted manifest metadata needed for recovery;
- salts, nonces, and tags needed to unwrap keys.

Header backup must not contain:

- plaintext DEK;
- plaintext MEK;
- plaintext user passwords;
- raw keyfile material;
- decrypted manifest;
- decrypted payload.

Header backup is not a substitute for keyfiles or passwords. It protects against header corruption and accidental wrapper removal when a valid secret still exists.

## Access destruction

HSE2 may implement explicit access destruction by removing all wrappers or selected wrappers.

Required safety rules:

- Destructive operations must never run implicitly during normal decrypt.
- There must be a distinct command or GUI flow.
- Full access destruction must require a long confirmation phrase.
- The tool should recommend exporting a header backup before destructive wrapper changes.
- The operation should preserve ciphertext while removing unwrap capability.

The user-facing name should be `destroy access` or `永久销毁解锁能力`, not a default `nuke password`.

## Duress and decoy handling

Duress or decoy support is deferred. If added later, it must open decoy content rather than silently deleting real access material.

A future duress wrapper should be documented as a limited decoy mechanism, not a full plausible-deniability guarantee.

## Error behavior

HSE2 errors should remain stable and non-leaky.

Recommended behavior:

- wrong password, wrong keyfile, corrupted wrapper, and authentication failure should produce concise authentication/integrity errors;
- debug mode may provide more detail for development, but must not reveal secrets;
- missing provider material should produce a provider error rather than an integrity error;
- wrapper enumeration should not reveal plaintext key material.

## Implementation stages

1. Add pure data models for header, wrapper records, KDF profiles, and manifest policy.
2. Add deterministic header serialization and validation.
3. Add random DEK/MEK generation and AES-GCM key wrapping.
4. Add password, keyfile, password_keyfile, and DPAPI wrapper handlers.
5. Add header export and restore commands.
6. Add wrapper list/add/remove commands.
7. Add explicit destroy-access command.
8. Integrate hardened/paranoid defaults into CLI and HSE2 GUI.
9. Add end-to-end tests for wrong password, wrong keyfile, missing provider, header restore, wrapper removal, and payload tampering.

## Compatibility

HSE1 compatibility must remain unchanged. HSE1 fixed Argon2id parameters must not be altered because HSE1 does not serialize KDF parameters in the file header.

HSE2 code should live beside existing HSE1 code and avoid breaking existing CLI batch workflows. Migration from HSE1 to HSE2 should be explicit rather than automatic.