# HSE2 Container Format

This document freezes the initial HSE2 container direction for offline-hardening work. It is intentionally conservative: HSE2 is a file-level encrypted container format, not a disk-encryption or hidden-volume system.

## Goals

- Provide a self-describing encrypted container format.
- Support offline brute-force resistance through authenticated KDF metadata, strong Argon2id profiles, random data keys, and external wrapper material.
- Support multiple unlock wrappers for password, keyfile, password+keyfile, and Windows DPAPI workflows.
- Encrypt payload metadata by default for hardened and paranoid workflows.
- Support explicit header backup and explicit access destruction workflows.
- Provide bounded-memory streaming encryption/decryption in archive format v3 while retaining v2 compatibility.

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

HSE2 containers are single files. The v2 and v3 formats share an authenticated JSON header and key model, but their bodies differ:

```text
v2: fixed preamble | authenticated header | JSON body (manifest + all chunks)
v3: fixed preamble | authenticated header | MNF3 record | CHK3 records (exact EOF)
```

Archive paths and file names are stored only inside the encrypted manifest. There are no plaintext per-file names in the payload records, so random internal aliases would not add at-rest filename privacy. The header's `filename_policy: "encrypted"` records this behavior; the authenticated header and ciphertext still expose aggregate layout such as total chunk count and container size.

Version 2 is retained for compatibility and remains the default output format. Its JSON body is materialized by existing v2 workflows, so memory use can grow with archive size. Version 3 is the binary streaming format; create selects it with `--format-version 3`, and open detects the version from the preamble. Do not reinterpret, migrate, or rewrite an existing v2 container as v3 implicitly.

## Fixed preamble

The preamble is the minimal unencrypted data needed to identify and parse the container.

Required fields:

| Field | Purpose |
|---|---|
| `magic` | Constant `HSE2` marker. |
| `format_version` | Integer format version: `2` for the JSON-body format or `3` for binary streaming. |
| `header_length` | Length of the serialized authenticated header. |
| `header_encoding` | Initial value: `canonical-json`. |

The preamble is 16 bytes, big-endian (`>4sBBHQ`): magic, version, header encoding, zero reserved field, and unsigned 64-bit header length. The preamble must not contain passwords, key material, file names, source paths, or KDF salts. Header JSON is canonical UTF-8 JSON in both versions.

### Version 3 streaming body

After the authenticated header, v3 stores one manifest record followed by exactly `payload_layout.chunk_count` payload records. All integer fields are unsigned big-endian. There is no footer; readers must reject truncation, wrong record order, unexpected chunk indices, and any trailing bytes.

```text
MNF3 | ciphertext_length:u64 | nonce:12 bytes | ciphertext:N | tag:16 bytes
CHK3 | index:u64 | ciphertext_length:u32 | nonce:12 bytes | ciphertext:N | tag:16 bytes
```

The manifest ciphertext is limited to 64 MiB; each chunk is limited to 16 MiB and to the authenticated `cipher_suite.chunk_size`. The header is limited to 1 MiB. `chunk_size` is 1 byte through 16 MiB. `payload_layout.payload_offset` and `footer_offset` are reserved and must be zero in v3. Unpadded payload chunk AAD remains `HSE2:payload-chunk:v1:{global-index}`. The manifest is authenticated with AES-256-GCM, and its existing domain-separated AAD remains unchanged.

`payload_layout.padding_mode` is omitted for the default `none` mode. The opt-in `last-chunk-to-chunk-size` mode encrypts each non-empty file's final chunk at exactly `chunk_size` bytes, filling any remainder with cryptographically random bytes. Its original length remains in the encrypted manifest; open authenticates each padded chunk and writes only the declared original bytes. Padded chunks use a separate AAD context, and the mode is covered by the header authentication tag. This hides each file's exact size within a chunk-size interval, while total chunk count and approximate container size remain visible. It can add up to one chunk of storage per non-empty file. Readers that do not support the mode fail authentication rather than silently restoring padded bytes.

V3 readers authenticate the header before reading the manifest or payload. They validate the manifest and safe output paths before creating restored files, then decrypt to per-file staging outputs and atomically commit complete files. A later chunk failure may leave previously completed files in place; whole-directory all-or-nothing restore is not promised.

### Version 2 compatibility body

Version 2 retains the existing JSON body framing and v2 reader/writer behavior. Its `payload_chunks` array stores Base64 nonce, ciphertext, and authentication tag fields. V2 remains readable; it does not gain v3 bounded-memory guarantees. Header backup metadata v1 remains compatible with v2, while v3 uses its own metadata format.

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

When the opt-in padding mode is enabled, `payload_layout` also contains
`"padding_mode": "last-chunk-to-chunk-size"`.

The header authentication tag must cover all security-critical header fields, including KDF parameters, wrapper metadata, cipher selections, manifest policy, payload layout, and nonce/salt fields that influence decryption.

For v3, the authenticated header declares the exact chunk count and chunk size used by the streaming body. V3 reserved offsets are zero; sequential framing, authenticated counts, AEAD tags, and exact EOF provide the record boundaries and completeness checks.

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

Wrapper add/remove/rewrap and explicit access destruction in v3 authenticate the existing header, write a new authenticated header, and copy the encrypted body in fixed-size blocks. They preserve the body bytes and do not re-encrypt payload chunks.

## Compatibility policy

- Readers dispatch by preamble version and reject unknown versions; they never infer a format from body contents.
- V2 remains the default create format for compatibility. V3 creation is explicit until a separate release policy changes this default.
- V2 remains readable by this implementation. V3 requires a v3-capable reader; older implementations reject it as an unsupported version.
- HSE1 files are migrated explicitly through the HSE1-to-HSE2 workflow. Migration writes a new output and preserves the original input; it is not an in-place upgrade.
- V2 and v3 use different body framing. A format change requires an explicit version dispatch and must not silently reinterpret existing bytes.

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

`hardened` is the default for new HSE2 encryption. Password-backed `paranoid` archive creation requires both a password and a keyfile; password-only creation is rejected. Keyfile-only and explicit DPAPI wrappers remain available as separate wrapper choices. The create CLI applies this policy to both normal creation and dry-run planning.

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

## Guarded create/open CLI staging

The first HSE2 create/open CLI workflows must remain guarded until inspect and archive-planning behavior stays stable under CI.

Initial create/open CLI staging rules:

- create commands should support a metadata-only or dry-run mode before writing `.hse2` output;
- open commands should inspect and authenticate container structure before attempting manifest or payload decryption;
- validation failures must write diagnostics to stderr and avoid partial plaintext output on stdout;
- destructive actions, wrapper removal, and access-destruction flows must stay out of the initial create/open command path;
- GUI integration should consume the same command semantics rather than inventing separate security behavior.

## Error behavior

HSE2 errors should remain stable and non-leaky.

Recommended behavior:

- wrong password, wrong keyfile, corrupted wrapper, and authentication failure should produce concise authentication/integrity errors;
- debug mode may provide more detail for development, but must not reveal secrets;
- missing provider material should produce a provider error rather than an integrity error;
- wrapper enumeration should not reveal plaintext key material.
