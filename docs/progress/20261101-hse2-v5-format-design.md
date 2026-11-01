# HSE2 v5 Compact Alternate-View Format Design

**Status: locally frozen implementation baseline; codec implementation has started.**
**Date: 2026-11-01**

This document defines a compact, explicitly disclosed two-view container. It makes no claim of plausible deniability, hidden-volume behavior, coercion resistance, anti-forensics, or secure deletion. It does not change v2, v3, or v4. Implement v5 in isolated modules and add a new format dispatch path; do not refactor the released readers as part of the first implementation.

## 1. Design goals

- Keep exactly two password-selected alternate views, matching the user-facing v4 concept.
- Remove v4's fixed 128 MiB descriptor reservation and fixed-size 1 MiB record allocation.
- Permit one view to be updated while preserving the peer view byte-for-byte without asking for its password.
- Bound every parser allocation and every writer's physical output before using untrusted lengths.
- Stream file content with a fixed chunk buffer; keep v2/v3/v4 fixtures and behavior unchanged.
- Make replacement append-only. Old encrypted objects can remain in the output; reclamation is an explicit operation requiring both view credentials.

## 2. Public framing

All integers are unsigned big-endian. The file is:

```text
fixed header | opaque append-only object area | fixed footer
```

### 2.1 Fixed header

```text
magic:4 = "HSE2" | version:u8 = 5 | encoding:u8 = 2 |
flags:u16 = 0 | archive_id:16 random bytes |
credential_slot_0:77 | credential_slot_1:77
```

The header is exactly 178 bytes. `archive_id` is generated once with the system CSPRNG and remains unchanged across ordinary updates. Each 77-byte credential slot retains the v4 field shape: profile id `u8`, Argon2id salt 16 bytes, GCM nonce 12 bytes, wrapped 32-byte view-root key, and 16-byte tag. Both slots must use the same allowlisted Argon2id profile. Password byte strings must differ. Slot AAD is ASCII `HSE2:v5:credential:<archive-id-hex>:<slot>:<profile-id>:v1`.

Each view has an independently generated 32-byte root key. The password KEK wraps only its assigned root key. Unlock performs both same-shape KDF attempts and accepts exactly one authenticated slot; all failures map to one generic credential/format error. The public version and two slots openly disclose alternate-view support.

### 2.2 Footer

The exact 56-byte footer is:

```text
magic:4 = "H5FT" | footer_version:u16 = 1 | reserved:u16 = 0 |
view_0_descriptor_offset:u64 | view_0_descriptor_length:u64 | view_0_generation:u64 |
view_1_descriptor_offset:u64 | view_1_descriptor_length:u64 | view_1_generation:u64
```

Both views always have a descriptor, including an empty view. An empty view is an authenticated descriptor with an empty file map; this prevents changing a pointer to zero from silently turning a non-empty view into an apparently valid empty view. Each entry has generation >= 1 and a descriptor length from 60 bytes through 16 MiB. A reader locates this footer only at EOF, validates the exact footer size and all offset/length bounds, and rejects trailing bytes. Footer pointers are public and unauthenticated as a pair; the selected descriptor authenticates its own slot, generation, offset, and length. Opening one view cannot cryptographically validate the peer pointer. Updates preserve the peer pointer fields unchanged and perform structural bounds checks on them.

Descriptor pointer rollback is possible for an attacker who can replace the whole file with an older valid snapshot. There is no trusted external monotonic counter, so v5 does not claim rollback detection. Repeated copies can reveal growth and historical encrypted data.

### 2.3 Opaque object area

The object area begins immediately after the header and ends immediately before the footer. It is an append-only byte sequence of records and encrypted descriptors from all generations. There is no public record index, occupied/free bitmap, per-view count, or per-record length prefix. Active offsets and lengths are only present in the encrypted descriptor for the selected view. Total file length still reveals aggregate storage and update growth.

Each new record is encoded as:

```text
hkdf_salt:32 | nonce:12 | ciphertext:N | tag:16
```

`N` is 1 through 1,048,576 bytes. A zero-length file has no record. The encrypted descriptor maps each chunk to `(sequence:u64, offset:u64, plaintext_length:u32)`. Record blob length is exactly `60 + plaintext_length`. Records are contiguous during initial creation and appended during later updates. A current manifest may reference earlier records and records appended in the current generation; it cannot reference the current descriptor or footer.

Each record key is HKDF-SHA-256 from the selected view root key, the record's fresh 32-byte salt, and ASCII info `HSE2:v5:view:<slot>:record:<sequence>:v1`. Each record uses one fresh random 12-byte AES-256-GCM nonce. Record AAD is the byte sequence `HSE2:v5:record:v1` followed by the 16-byte archive id, slot `u8`, sequence `u64`, physical offset `u64`, and plaintext length `u32`, in that order. The sequence must be unique within the current live descriptor for a view. Writers never rewrite an existing record blob; replacement always appends new ciphertext. HKDF salt and nonce are regenerated for every new record. A ciphertext/tag/offset/length/slot/sequence change fails authentication.

The design deliberately exposes total container length and append growth; it does not add padding or pretend those observations are hidden.

### 2.4 Encrypted view descriptor

The descriptor blob is:

```text
hkdf_salt:32 | nonce:12 | ciphertext:N | tag:16
```

The plaintext is canonical UTF-8 JSON with duplicate keys and non-finite JSON constants rejected. It contains a schema version, slot, generation, next record sequence, sorted file entries, and chunk references. `slot` and `generation` must match the footer entry. Each file entry contains a normalized relative path, exact plaintext size, and ordered chunk references; summed chunk lengths must equal file size. Empty files have an empty chunk list. Reject duplicate paths, unsafe paths, overlapping physical record spans, duplicate sequence values, non-canonical JSON, unsupported fields/versions, and chunks outside all limits before creating any plaintext output.

Descriptor key: HKDF-SHA-256 from the view root key, fresh 32-byte salt, and ASCII info `HSE2:v5:view:<slot>:descriptor:<generation>:v1`. Use one fresh 12-byte AES-256-GCM nonce per descriptor. Descriptor AAD is `HSE2:v5:descriptor:v1` followed by archive id (16), slot (`u8`), generation (`u64`), descriptor offset (`u64`), and complete blob length (`u32`), all integers big-endian. The offset and length in AAD mean changing the footer pointer to a different location or length causes authentication failure. Replaying an old descriptor together with its old pointer remains possible and is covered by the rollback limitation above.

The descriptor ciphertext is at most 16 MiB; its plaintext contains no padding. Readers validate the footer's descriptor length before reading and decrypting it. The writer validates the serialized plaintext size before encryption and the resulting blob size before publishing. Both pointers are mandatory and descriptor lengths are public, so an observer can distinguish an empty view from a populated one and estimate metadata size; v5 makes no attempt to conceal this.

## 3. Resource limits and acceptance targets

Hard parser/writer ceilings:

- Maximum whole container size: 64 GiB, including header, all generations, descriptors, and footer.
- Maximum plaintext chunk: 1 MiB; maximum live chunks: 32,768 per view.
- Maximum active encrypted descriptor blob: 16 MiB per view.
- Maximum file entries in one active view: 100,000; maximum UTF-8 relative path: 4,096 bytes.
- Maximum parsed JSON nesting depth: 32; descriptor byte cap is checked before JSON parsing. Measure Python object expansion and keep incremental parser working-set growth within 256 MiB on the maximum-manifest fixture.
- Reject over-limit values before reading their declared content or allocating a corresponding buffer.
- Stream with a 1 MiB data buffer plus bounded header/footer and descriptor state. JSON object expansion can exceed serialized manifest bytes and must be measured separately.

Initial output-size targets (freeze after implementation measurements; do not represent current v5 results):

- Empty two-view archive: <= 1 KiB (header + footer is 234 bytes; two compact authenticated empty descriptors bring it to roughly 0.5 KiB).
- One-byte file in one view: <= 2 MiB.
- One-byte file in each view: <= 3 MiB.
- One MiB single-view file: <= 1.1 MiB.
- Compare create and replace time, output size, and peak working set against the v4 baseline using the same machine, inputs, KDF profile, and repeated runs. Do not call a single sample an improvement.

The size targets are engineering goals, not security properties. There is no fixed per-view reservation. The hard 64 GiB physical cap includes stale data from previous generations, so a container may reach the cap before its active files do. Active chunk and entry limits bound parsing of the selected view; stale opaque bytes are not scanned on open. Every write checks the resulting whole-file size before publishing.

## 4. Create, open, replace, and space reclamation

### Create

Generate archive id, both view roots, salts, nonces, and credential slots. Write the fixed header, then stream each view's file chunks to the object area and build its bounded descriptor. Append the two descriptors and footer. Write to a same-directory staging file; flush and fsync according to the existing `HSE_FSYNC` policy; publish only after all bytes and footer are complete. Never read a user file wholly into memory.

### Open

Validate fixed header and footer bounds before credential KDF work. Unlock exactly one credential slot, authenticate its descriptor, validate all paths/ranges/limits and target conflicts before creating restore files, then stream records to per-file staging files. Authenticate each record before committing that file. Failure removes the current file's staging output; previously committed complete files may remain, consistent with v3's per-file commit behavior. Do not claim whole-directory all-or-nothing restore.

### Replace one view

Require a distinct output path; preserve the source archive. Validate and unlock the selected view, build a new active manifest, append only new/replaced records, append the new descriptor, and write a new footer. Carry the peer descriptor pointer/generation exactly as present in the source footer. The peer's active descriptor and records are copied as opaque bytes and its password is not required. Removed/replaced old records remain encrypted but unreferenced. On any failure, remove the staging output and preserve the source and any pre-existing destination according to overwrite policy.

### Compact and migrate

Space reclamation is a separate explicit `compact/export` operation that requires both view passwords, authenticates both active views, writes a fresh v5 container containing only current content, and leaves the original untouched. V4-to-v5 migration also requires both passwords to preserve both views; it writes a new destination and never upgrades in place. The UI and CLI must clearly say that the operation reads/decrypts both views and creates a new archive. No automatic compaction occurs during single-view replace because the program cannot preserve an inaccessible peer's current content in a compact archive.

### Durability boundary

Same-directory staging plus `os.replace` provides atomic visibility where supported; it does not by itself prove power-loss durability. `HSE_FSYNC=1` is an existing opt-in and must be applied consistently. Phase 4 will inject failures at write, flush/fsync, replace, and cleanup boundaries and document only tested platform/filesystem behavior. V5 does not promise recovery of a corrupt source or guaranteed removal of old encrypted/plaintext blocks from SSDs, snapshots, journals, or backups.

## 5. Compatibility and version dispatch

- V2, v3, and v4 readers and writers remain unchanged. New v5 reads/writes use isolated modules and explicit `version == 5` dispatch.
- Never infer v5 from extension or file size. Reject unknown versions and malformed fixed framing before KDF or output creation.
- V4-to-v5 and v5 compact/export always create a distinct output. Keep existing v2/v3/v4 fixture hashes and round-trip tests.
- A release must include stable v5 byte fixtures, fixed primitive/record/descriptor vectors with test-only keys, malformed-footer/descriptor bounds tests, tamper tests for every AAD-bound field, both-view isolation and opaque-peer-preservation tests, migration/compaction tests, interrupted-write tests, and the full legacy regression suite.

## 6. Deliberate non-goals and remaining implementation validation

- No plausible deniability, hidden views, equal-size camouflage, automatic deletion, or coercion response.
- No rollback resistance without a separate trusted monotonic state source.
- No secure deletion of stale encrypted records or operating-system snapshots.
- No claim that public container length hides total content size or update history.
- No cross-filesystem atomicity guarantee; updates must stage beside the destination.
- This document freezes a locally reviewed design for implementation. It is not cryptographic certification; local implementation tests remain mandatory.

## 7. Implementation sequence

1. Add isolated v5 framing/credential/record/descriptor codecs and fixed deterministic test vectors.
2. Add bounded streaming create/open and per-view replace while preserving opaque peer data.
3. Add explicit two-credential compaction and v4-to-v5 export.
4. Add failure injection, resource regression measurements, CLI/GUI surfaces, and Windows package acceptance.
