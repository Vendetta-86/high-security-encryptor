# HSE2 Phase 8: alternate-view container proposal (review draft)

## Status and scope

**Status: self-use candidate; isolated codecs, fixed-layout file workflows, and experimental Python CLI commands exist. The local PyInstaller CLI EXE has passed create and both-view restore smoke tests; GUI and full Release ZIP integration remain incomplete.** This proposal explores an explicitly limited alternate-view feature in a new container version. It does not authorize changes to HSE2 v2/v3 or any claim of plausible deniability. The intended user-visible term is **alternate view**, not hidden volume or duress protection.

The current Phase 8 design review correctly rejects a visible `duress` wrapper, a second manifest/payload family, and reuse of v2/v3 for a deniability claim. This draft preserves those findings and turns the next review questions into explicit gates.

## Proposed security claim

Candidate claim for review: for a **single, static copy of a new-version container**, an offline observer without either credential should not be able to distinguish whether the secondary view is empty or contains files, beyond the public v4 format marker, the existence of two credential slots, fixed capacity, and total container length.

This claim is not made yet. The v4 marker and two credential slots publicly reveal that the format supports two views; the proposal does not hide that capability. Repeated snapshots, host artifacts, application execution, coercion safety, key disclosure, secure deletion, and resistance to a maliciously modified application are excluded. Users must be told that filenames, logs, temporary files, backups, cloud sync, and operating-system traces can disclose opened content. No UI or documentation may promise protection from coercion.

## Candidate architecture questions (deliberately unresolved)

1. A new format version must retain a single public header/wrapper shape. No public wrapper type, flag, record label, or inspect result may announce the second view.
2. Each credential must authenticate and unwrap only its assigned view. Failed authentication must return one generic error and must not reveal which view exists.
3. Both views must use the same record grammar, authenticated fields, and parsing path. No view-specific record type or count may be public.
4. The proposal must define whether view bytes use fixed-size allocation, encrypted allocation metadata, or an alternate construction. It must analyze total length, chunk counts, update deltas, padding distribution, backups, and crash recovery. No choice is approved here.
5. Key derivation must be domain-separated by format version, view role, and key purpose. The derivation tree, nonce uniqueness argument, authentication coverage, and key-rotation behavior must be reviewed before implementation.
6. Opening or updating one view must never overwrite, truncate, or silently destroy the other view. Atomic update and recovery behavior must be specified for interruption at every write boundary.

These constraints do not prove indistinguishability. In particular, simple concatenation, a visible second wrapper, or one-time equal-size output does not meet the proposed claim.

## Concrete candidate: fixed-capacity two-view v4 (self-review draft)

This narrows the feature to **exactly two password-selected views**. Every v4 archive has two same-shaped credential slots and two same-shaped encrypted view descriptors; the format does not support a one-view v4 archive. The public format reveals that dual-view capability exists; only whether the secondary view contains data is intended to remain private.

### Public layout

```text
170-byte public header | 64 MiB descriptor slot 0 | 64 MiB descriptor slot 1 | fixed-capacity record area
```

- The public header is a 16-byte `>4sBBHII` prefix (`HSE2`, version 4, binary encoding 2, zero reserved bits, record capacity, descriptor-region size 67,108,864), followed by two 77-byte structurally identical credential slots. Its total fixed length is 170 bytes; record size is fixed by v4 at 1,048,576 bytes.
- Each credential slot is exactly 77 bytes: one-byte profile ID (`1` compatible, `2` hardened), 16-byte random Argon2id salt, 12-byte random GCM nonce, 32-byte ciphertext, and 16-byte tag. Both slots use the same allowlisted profile. Slot AAD is ASCII `HSE2:v4:credential:<slot>:<capacity-records>:1048576:67108864:<profile-id>:v1`. No labels, timestamps, view names, or wrapper types are present. Passwords are UTF-8 encoded without Unicode normalization; creation rejects identical encoded bytes. Unlock runs Argon2id for both slots and succeeds only if exactly one authenticates; zero or two matches produce the same generic failure.
- Each view descriptor occupies a fixed 64 MiB region at a fixed public position. Its first 32 bytes are a random HKDF salt, followed by a 12-byte GCM nonce, then exactly 67,108,804 bytes of AES-256-GCM ciphertext and a 16-byte tag under a one-use descriptor key derived from that view root. These fields total 67,108,864 bytes. The private descriptor contains a canonical JSON manifest (maximum 63 MiB), record-index/length map, and authenticated logical lengths; random plaintext padding fills the ciphertext to its fixed public size.
- The remaining area consists only of fixed-size records. Records referenced by either view contain AEAD ciphertext; unallocated records contain cryptographically random bytes. No plaintext occupied/free marker or per-view record count is stored.
- The public capacity is an even number from 2 through 65,536 records. Even physical record indices belong to slot 0 and odd indices belong to slot 1, so each view has exactly half of the advertised record capacity and can allocate without decrypting the other descriptor. This public partition fixes the non-overlap invariant. The total file size is selected at creation and does not grow during updates. The record area is at most 64 GiB; the manifest cap is 63 MiB so the largest record map also fits in its fixed descriptor. These are parser/resource ceilings, not promised device requirements. An update that cannot fit must fail without modifying the original. A larger capacity requires explicit export to a new archive and must be documented as a snapshot-visible operation.

### Key derivation and encryption constraints

- Each of the two view root keys is generated independently with a CSPRNG; credentials never directly encrypt content.
- Argon2id derives one KEK per password using independent 16-byte random salts and the existing bounded profile allowlist. Both slots always serialize the same profile and lengths.
- AEAD wraps each root key with AAD binding format version, public capacity, slot index, and the complete immutable public header fields. The exact encoding must be canonical and covered by test vectors.
- Use PyCryptodome's RFC 5869 HKDF-SHA-256 primitive, already supplied by the pinned dependency family. HKDF info strings are ASCII `HSE2:v4:view:<slot>:manifest:v1` and `HSE2:v4:view:<slot>:record-wrap:<record-index>:v1`; fresh per-object salts are independent. Capacity is bound by AEAD AAD, not by changing HKDF inputs. No archive identifier is currently defined. View roots and derived keys are never shared across slots or purposes.
- Each descriptor generation uses a fresh HKDF salt, derived key, and random 96-bit GCM nonce for exactly one AES-GCM encryption. The 2^20 rewrite ceiling is a resource policy, not a per-key GCM invocation allowance. Each data record gets a fresh random 256-bit content key, used for exactly one AES-256-GCM encryption; its key is wrapped under an HKDF-derived per-record wrapping key using a fixed all-zero 96-bit nonce and authenticated fields for version, slot, index, and record size. The HKDF salt is 32 fresh random bytes per record. Never re-encrypt different plaintext under the same record key.
- Each password slot uses existing Argon2id profiles, but v4 permits only compatible/hardened (no 1 GiB profile for routine dual unlock); profile and parameters are authenticated by the slot's wrapped-key AEAD. The two slots must use the same profile and fixed lengths. Argon2 work happens only after caller explicitly enters a password; the application attempts both same-shaped slots and reports one generic unlock failure if neither authenticates.

### Fixed record bytes

Each 1 MiB record is exactly:

```text
hkdf_salt:32 | wrapped_record_key:32 | wrap_tag:16 | payload_nonce:12 |
payload_ciphertext:1,048,468 | payload_tag:16
```

The record-key plaintext is a fresh random 32-byte key. The wrapped key uses AES-256-GCM under the per-view/per-index HKDF key, a fixed all-zero 96-bit nonce (one encryption per derived key), and ASCII AAD `HSE2:v4:record-key:<slot>:<index>:1048576:v1`. The payload uses AES-256-GCM under the random record key and fresh random 96-bit `payload_nonce`; its plaintext is always exactly 1,048,468 bytes. Its ASCII AAD is `HSE2:v4:record-payload:<slot>:<index>:1048576:v1`. Short final chunks are padded with cryptographically random bytes, and true lengths exist only in the encrypted descriptor. A record key is never reused for another payload encryption. The stored record is the concatenation shown above, with no alignment bytes or implicit fields.

Each view descriptor has a fresh 32-byte HKDF salt and derives its descriptor key with ASCII info `HSE2:v4:view:<slot>:descriptor:v1`; it is used for exactly one AES-GCM encryption with a fresh random 96-bit nonce. Ciphertext is padded to exactly 67,108,804 bytes, followed by the 16-byte tag, for a fixed 64 MiB region. The ciphertext plaintext begins with `>4sBBII` fields (`H4VD`, descriptor version 1, slot, manifest byte length, record count), then `record_count` sorted `>II` pairs (record index, logical byte length), then canonical UTF-8 JSON manifest bytes, then random padding. The record count cannot exceed capacity, indices are unique and below capacity, and each logical length is 1 through 1,048,468. Descriptor AEAD AAD is ASCII `HSE2:v4:descriptor:<slot>:<capacity-records>:1048576:67108864:v1`. A new descriptor key is derived on every output generation.
- The public header is not authenticated globally. Each credential slot authenticates its own root key; each descriptor and data record authenticates its own contents and index. Parsers must reject any malformed length or index before allocating from attacker-controlled values.

### Read/write behavior

- Unlock tries only the selected credential slot. All failures, including wrong password, bad wrapped key, malformed descriptor and tampering, produce one generic error before any plaintext output path is created.
- After unlock, the authenticated descriptor provides a set of record indices. Every listed index must be in range, unique within that view, belong to its public parity partition, and authenticate with the expected view/index AAD. The two views cannot reference the same physical record because their index namespaces are disjoint.
- Restore writes to staging files and commits only after the selected view has fully authenticated. The other view and its records are never modified by open or restore.
- Adding or replacing content allocates unused indices from that view's public parity partition and atomically writes a new fixed-size file. The writer copies the other descriptor and record area as opaque bytes, preserving the other view; changed records use fresh content keys. Old unreferenced records may remain ciphertext in the new copy, which is indistinguishable from random record bytes but is not secure deletion. The original remains intact on any failure.
- This design does not protect against repeated snapshots, host artifacts, file-size comparison across exports, opened plaintext traces, timing/memory observation, or an attacker who knows the application. It must not be marketed as coercion-safe or as general plausible deniability.

### Deterministic primitive vector (primitive check only)

Generated with the installed PyCryptodome 4.2.0; this is a regression vector for HKDF and AES-GCM composition, not a full container vector. All values below are fixed test inputs and must never be used for real archives.

| Input/output | Hex or value |
|---|---|
| IKM | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| HKDF salt | `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f` |
| HKDF info | ASCII `HSE2:v4:view:0:record-wrap:7:v1` |
| derived 32-byte key | `1f357c1b5768c99fd7d2211a92193393d8e02c80cd246ce4e9f34e0b6c55c0fe` |
| GCM nonce | 12 zero bytes (test-only) |
| GCM AAD | ASCII `HSE2:v4:slot:0:index:7:size:1048576` |
| plaintext | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| ciphertext | `9fc1f749c79556f60a2d490714566a538a72dadeb61517ab9aa26ea86667dbbb` |
| tag | `761fa63653ab7d9d2595ad795da3c149` |

The file helper copies to a same-directory temporary output and patches only the selected view; a round-trip test confirms that input and peer-view bytes remain unchanged. This has not been interruption-tested at each write boundary. The repository's `atomic_output_path` uses `os.replace`, which gives atomic replacement semantics where the filesystem supports them but does not promise power-loss durability unless `HSE_FSYNC=1`. Updates always publish to a different path and preserve the input.

### Local review questions that remain before release integration

1. Is the fixed descriptor placement and identical pair of credential slots sufficient for the narrowly stated single-copy container model? The baseline is always exactly two valid views; an empty secondary view is permitted, and the feature never claims to hide that two-view support exists or to conceal content after credential disclosure.
2. Are the 1 MiB record, 65,536-record, 64 GiB record area, two 64 MiB descriptor regions, and 63 MiB private manifest ceiling acceptable on supported Windows systems, including full-file atomic rewrite costs?
3. **Resolved locally for isolated codecs:** HKDF-SHA-256 and AES-256-GCM primitive behavior and the byte-exact vector pass on PyCryptodome 3.20.0 (declared minimum) and 4.2.0. Record-key wrapping, fixed-size record parsing, dual credential slots, descriptor encryption, and public-header size checks have local round-trip/tamper tests. These do not validate whole-file I/O, update atomicity, or alternate-view indistinguishability.
4. **Partially tested locally:** the file helper preserves the input and publishes through the repository's atomic replacement helper. Process interruption at every write boundary, power-loss durability, and all supported filesystem behavior remain untested.
5. What property tests and fuzz limits demonstrate fail-closed behavior? Which claims remain assumptions rather than tests?

**Decision:** this remains an experimental self-use candidate, not an approved cryptographic construction. Primitive compatibility, byte layout, AAD, record partitioning, file workflows, and Python CLI paths have local tests. Questions 1, 2, and 5 remain open; interruption and filesystem coverage in question 4 are partial. Before stable release packaging, the project must validate resource use, add bounded malformed-input/property tests, and evaluate the narrowly scoped claim. The current implementation does not establish container safety or plausible deniability.

## Local review package

Before implementation, the project owner must review the exact versioned wire proposal, reference parser/writer, threat model, test corpus, and list of excluded claims. The recorded self-review must cover:

- cryptographic construction and key hierarchy, domain separation, nonce generation, AEAD limits, and authentication coverage;
- distinguishability from public fields, ciphertext length, malformed inputs, errors, timing, backups, and repeated snapshots within the stated scope;
- parser safety, downgrade behavior, resource limits, atomic updates, and recovery after partial writes;
- independent implementation feasibility and a test vector format, as local analysis only.

The review result must identify the reviewed commit/digest, findings, severity, and unresolved assumptions. This is an internal self-use review, not third-party certification.

## Implementation gates

No production code until the local review records and resolves blocking findings. Implementation must use a new format version and separate modules; v2/v3 readers must continue to reject it as unsupported. Required tests include positive and negative credential paths, tampering, truncation, field mutation, generic failure behavior, fuzzing, memory/time limits, interrupted updates, backup/restore, downgrade attempts, and a separately written local reference implementation. These tests can find defects but cannot establish real-world deniability outside the stated model.

## Source basis and limitations

- NIST SP 800-38D specifies GCM and is under revision; the current format already imposes a per-key invocation bound for random 96-bit IVs. A new format must re-evaluate this bound against the chosen nonce construction and usage model: https://csrc.nist.gov/pubs/sp/800/38/d/final
- RFC 9106 specifies Argon2; it informs password KDF requirements but does not solve alternate-view indistinguishability: https://www.rfc-editor.org/rfc/rfc9106
- VeraCrypt's own hidden-volume guidance documents operational limits and host-system exposure. It is a product-specific reference, not evidence that this file-container design inherits VeraCrypt's properties: https://veracrypt.io/en/Security%20Requirements%20for%20Hidden%20Volumes.html

This draft is an internal design artifact and has not been externally certified.
