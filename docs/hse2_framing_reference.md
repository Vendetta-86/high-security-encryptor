# HSE2 Framing Reference

This document records the HSE2 v2 and v3 byte and JSON framing used by the implementation. It is a reference for contributors and release review, not a stable-format guarantee by itself. Unless a section explicitly says v3, the JSON body description below is the legacy v2 format.

The broader stable-format contract remains governed by `docs/hse2_format.md` and future format-freeze release notes.

## Scope

This reference covers:

- the fixed preamble byte layout;
- authenticated header serialization;
- body JSON serialization;
- encrypted manifest metadata framing;
- encrypted payload chunk framing;
- header authentication coverage;
- compatibility notes for alpha readers and writers.
- v3 binary streaming records and resource limits.

It does not redefine cryptographic policy, user-facing workflows, key backup policy, or GUI behavior.

## Container byte layout

Version 2 alpha HSE2 containers are encoded as:

```text
[preamble][header_json][body_json]
```

There is no separate delimiter between `header_json` and `body_json`. The reader uses the fixed-size preamble and declared `header_length` to split the header from the body.

## Fixed preamble

The preamble is exactly 16 bytes in both versions and is packed big-endian with this Python struct format:

```text
>4sBBH Q
```

The fields are:

| Offset | Size | Field | Type | Current value / meaning |
|---:|---:|---|---|---|
| 0 | 4 | `magic` | bytes | `HSE2` |
| 4 | 1 | `format_version` | unsigned byte | `2` |
| 5 | 1 | `header_encoding` | unsigned byte | `1`, meaning canonical JSON |
| 6 | 2 | `reserved` | unsigned short | must be `0` |
| 8 | 8 | `header_length` | unsigned long long | byte length of `header_json` |

Validation rules:

- `magic` must equal `HSE2`.
- `format_version` must equal `2`.
- `header_encoding` must equal `1`.
- `reserved` must equal `0`.
- `header_length` must be non-negative and fit the available bytes.

## Canonical JSON rules

Current header and body JSON are serialized with deterministic JSON settings equivalent to:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

The practical consequences are:

- object keys are sorted;
- no insignificant whitespace is emitted;
- strings are UTF-8 encoded;
- non-JSON values are rejected before serialization.

Readers must not depend on pretty-printed JSON or field order in source code. Writers should use the canonical serializer for any authenticated or stored HSE2 JSON sections.

## Authenticated header JSON

`header_json` is canonical JSON for an `HSE2Header` object. The stored header includes the auth tag when present.

Current top-level header fields are:

```json
{
  "access_destroyed": true,
  "cipher_suite": {},
  "created_utc": "...",
  "format": "HSE2",
  "format_version": 2,
  "header_auth": {},
  "manifest_policy": {},
  "payload_layout": {},
  "wrappers": []
}
```

`access_destroyed` is omitted when false and included only when true.

### `cipher_suite`

Current fields:

```json
{
  "payload_cipher": "AES-256-GCM",
  "manifest_cipher": "AES-256-GCM",
  "wrap_cipher": "AES-256-GCM",
  "chunk_size": 1048576
}
```

Current supported cipher value is `AES-256-GCM` for payload, manifest, and wrapper encryption.

### `manifest_policy`

Current fields:

```json
{
  "encrypted": true,
  "store_original_paths": false,
  "filename_policy": "encrypted"
}
```

Allowed `filename_policy` values are:

- `encrypted`
- `randomized`
- `preserved`

The archive create workflow currently writes encrypted manifests and does not store original absolute paths by default.

### `payload_layout`

Current fields:

```json
{
  "chunk_count": 0,
  "payload_offset": 0,
  "footer_offset": 0
}
```

`chunk_count`, `payload_offset`, and `footer_offset` must be non-negative integers. Current alpha body framing is JSON-based, so `payload_offset` and `footer_offset` are layout metadata rather than offsets into a separate binary payload region.

### `header_auth`

Current fields:

```json
{
  "algorithm": "HMAC-SHA256",
  "tag": "base64..."
}
```

The tag is omitted when computing the tag and included when storing the header.

## Header authentication coverage

Header authentication uses HMAC-SHA256 with MEK as the HMAC key.

The MAC input is:

```text
HSE2:header-auth:v1 || canonical_header_json_without_header_auth_tag
```

The resulting digest is base64-encoded and stored as `header_auth.tag`.

The authenticated header therefore covers security-sensitive header content, including:

- cipher selections;
- manifest policy;
- payload layout;
- wrapper records;
- wrapper KDF metadata;
- wrapper nonces and tags;
- access status metadata when present.

## Wrapper record JSON

Each wrapper record is a JSON object in the header `wrappers` array.

Current fields:

```json
{
  "id": "password-1",
  "type": "password",
  "created_utc": "...",
  "label": "password",
  "kdf": {},
  "wrap_cipher": "AES-256-GCM",
  "nonce": "base64...",
  "wrapped_keys": {
    "dek": "base64...",
    "mek": "base64..."
  },
  "auth_tag": "base64..."
}
```

`label` and `kdf` are optional at the JSON model level, but password and password+keyfile wrappers require KDF metadata.

Supported current wrapper types are:

- `password`
- `keyfile`
- `password_keyfile`
- `dpapi`

### Wrapped DEK/MEK framing

The current implementation wraps DEK and MEK together in one AES-GCM operation:

```text
plaintext = DEK || MEK
```

Where both `DEK` and `MEK` are 32-byte values. The resulting 64-byte ciphertext is split into:

- `wrapped_keys.dek`
- `wrapped_keys.mek`

Both fields share the same wrapper `nonce` and wrapper `auth_tag`.

## KDF metadata

Password-based wrappers store explicit KDF metadata in the wrapper record. Current profile names are:

| Profile | `memory_cost_kib` | `time_cost` | `parallelism` | `hash_len` |
|---|---:|---:|---:|---:|
| `compatible` | 65536 | 3 | 4 | 32 |
| `hardened` | 262144 | 3 | 4 | 32 |
| `paranoid` | 1048576 | 4 | 4 | 32 |

Password wrappers include a base64 salt in KDF metadata. DPAPI wrappers store DPAPI-specific protected KEK metadata instead of Argon2id profile parameters.

## Body JSON

`body_json` is canonical JSON containing the encrypted manifest and encrypted payload chunks.

Current body shape:

```json
{
  "section_magic": "HSE2BODY\n",
  "manifest": {
    "nonce": "base64...",
    "ciphertext": "base64...",
    "auth_tag": "base64..."
  },
  "payload_chunks": [
    {
      "index": 0,
      "nonce": "base64...",
      "ciphertext": "base64...",
      "auth_tag": "base64..."
    }
  ]
}
```

Validation rules:

- `section_magic` must equal `HSE2BODY\n`.
- `manifest` must be a JSON object with `nonce`, `ciphertext`, and `auth_tag`.
- `payload_chunks` must be a JSON array.
- each payload chunk must include integer `index`, string `nonce`, string `ciphertext`, and string `auth_tag`.

## Encrypted manifest metadata

The manifest is encrypted as canonical JSON with MEK-backed AES-GCM.

Stored encrypted manifest fields are:

| Field | Type | Meaning |
|---|---|---|
| `nonce` | base64 string | AES-GCM nonce |
| `ciphertext` | base64 string | encrypted canonical manifest JSON |
| `auth_tag` | base64 string | AES-GCM authentication tag |

Manifest AAD is domain-separated with:

```text
HSE2:manifest:v1
```

## Encrypted payload chunks

Payload chunks are encrypted with DEK-backed AES-GCM.

Stored chunk fields are:

| Field | Type | Meaning |
|---|---|---|
| `index` | integer | zero-based chunk index |
| `nonce` | base64 string | AES-GCM nonce |
| `ciphertext` | base64 string | encrypted payload chunk bytes |
| `auth_tag` | base64 string | AES-GCM authentication tag |

Payload AAD is domain-separated per chunk:

```text
HSE2:payload-chunk:v1:{index}
```

Chunk indices must be non-negative integers.

## Compatibility notes

For alpha readers and writers:

- Treat unknown preamble versions as unsupported.
- Treat unknown header encodings as unsupported.
- Treat non-zero reserved preamble fields as invalid.
- Treat missing body section magic as invalid.
- Treat missing or malformed wrapper records as invalid.
- Treat failed header, manifest, wrapper, or payload authentication as integrity failure.

For future stable HSE2 releases:

- Any change to preamble structure should require a format-version bump.
- Any change to canonical JSON rules should require an explicit compatibility decision.
- Any change to body framing should document whether old alpha containers remain readable.
- HSE1 compatibility should remain a migration boundary, not an HSE2 byte-layout constraint.

## Version 3 binary streaming body

V3 uses the same 16-byte preamble shape and canonical JSON authenticated header, with preamble and header `format_version` both equal to `3`. Header JSON is limited to 1 MiB. The header is authenticated before any manifest or payload body read.

After the header, v3 is a sequence of raw binary records. All integer fields are unsigned big-endian. Nonces and tags are raw bytes, not Base64, in the body records.

### Manifest record

```text
offset  size  field
0       4     magic = "MNF3"
4       8     ciphertext_length (1..64 MiB)
12      12    AES-GCM nonce
24      N     ciphertext
24+N    16    AES-GCM tag
```

Exactly one manifest record must immediately follow the header. It is decrypted and validated before restore files are created.

### Payload chunk record

```text
offset  size  field
0       4     magic = "CHK3"
4       8     index (zero-based, contiguous)
12      4     ciphertext_length (1..authenticated chunk_size, max 16 MiB)
16      12    AES-GCM nonce
28      N     ciphertext
28+N    16    AES-GCM tag
```

Exactly `payload_layout.chunk_count` chunks follow the manifest. Each `index` must equal the next expected index. `chunk_size` is 1 byte through 16 MiB. `chunk_count` must not exceed 2^32, the per-DEK payload AES-GCM invocation limit for random 96-bit IVs (NIST SP 800-38D section 8.3). The same payload limit applies to v2. The authenticated header's `payload_layout.payload_offset` and `footer_offset` must both be zero; they are reserved in v3 and are not seek positions. After the declared chunks, the reader requires exact EOF; no footer or trailing data is allowed.

V3 payload AAD remains `HSE2:payload-chunk:v1:{global-index}`. This preserves the existing chunk AEAD definition. The authenticated chunk count, contiguous record indices, manifest ranges, GCM tags, and exact EOF jointly detect missing, reordered, altered, and extra records.

### V3 body limits and streaming behavior

- Header JSON: at most 1 MiB.
- Encrypted manifest ciphertext: at most 64 MiB.
- Chunk ciphertext: at most 16 MiB and at most authenticated `chunk_size`.
- Entry count: at most 1,000,000.
- UTF-8 relative path: at most 4,096 bytes.
- V3 create/open, wrapper body copying, and header-backup digest/restore use bounded buffers; manifest JSON parsing remains bounded by the manifest limit and may expand in memory.
- Create and wrapper rewrites use same-directory temporary outputs and replace the target only after successful completion. Restore commits each complete file from a same-directory staging file; already committed files may remain if a later chunk fails.

### Version dispatch and compatibility

- Preamble and header versions must match; unknown versions and encodings are rejected.
- V2 uses the JSON body documented above and does not have v3's bounded-memory guarantee.
- V2 remains the default output format. CLI v3 creation is explicit with `--format-version 3`; open dispatches automatically.
- Header backup v2 metadata remains supported; v3 has a versioned metadata format.
- HSE1 migration writes a new HSE2 output and preserves the original. There is no in-place reinterpretation of v2 bytes as v3.

## Status

This file documents the current alpha framing reference. It does not by itself declare HSE2 stable-format freeze complete.
