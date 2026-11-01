# HSE2 Phase 8: alternate-view container proposal (review draft)

## Status and scope

**Status: self-use design draft; local review required before implementation.** This proposal explores an explicitly limited alternate-view feature in a new container version. It does not authorize changes to HSE2 v2/v3 or any claim of plausible deniability. The intended user-visible term is **alternate view**, not hidden volume or duress protection.

The current Phase 8 design review correctly rejects a visible `duress` wrapper, a second manifest/payload family, and reuse of v2/v3 for a deniability claim. This draft preserves those findings and turns the next review questions into explicit gates.

## Proposed security claim

Candidate claim for review: for a **single, static copy of a new-version container**, an offline observer without either credential should not be able to distinguish a one-view container from a container configured with two independently authenticated views, beyond public fixed-format fields and total container length.

This claim is not made yet. Repeated snapshots, host artifacts, application execution, coercion safety, key disclosure, secure deletion, and resistance to a maliciously modified application are excluded. Users must be told that filenames, logs, temporary files, backups, cloud sync, and operating-system traces can disclose opened content. No UI or documentation may promise protection from coercion.

## Candidate architecture questions (deliberately unresolved)

1. A new format version must retain a single public header/wrapper shape. No public wrapper type, flag, record label, or inspect result may announce the second view.
2. Each credential must authenticate and unwrap only its assigned view. Failed authentication must return one generic error and must not reveal which view exists.
3. Both views must use the same record grammar, authenticated fields, and parsing path. No view-specific record type or count may be public.
4. The proposal must define whether view bytes use fixed-size allocation, encrypted allocation metadata, or an alternate construction. It must analyze total length, chunk counts, update deltas, padding distribution, backups, and crash recovery. No choice is approved here.
5. Key derivation must be domain-separated by format version, view role, and key purpose. The derivation tree, nonce uniqueness argument, authentication coverage, and key-rotation behavior must be reviewed before implementation.
6. Opening or updating one view must never overwrite, truncate, or silently destroy the other view. Atomic update and recovery behavior must be specified for interruption at every write boundary.

These constraints do not prove indistinguishability. In particular, simple concatenation, a visible second wrapper, or one-time equal-size output does not meet the proposed claim.

## Concrete candidate: fixed-capacity two-view v4 (self-review draft)

This narrows the feature to **exactly two password-selected views**. Every v4 archive has two same-shaped credential slots and two same-shaped encrypted view descriptors; the format does not support a one-view v4 archive. This removes “one vs two credential slots” as a public distinction, but does not establish that the views or file usage are indistinguishable.

### Public layout

```text
fixed preamble | fixed-size public header | fixed-capacity record area
```

- The public header contains only magic/version, fixed header length, public capacity, fixed record size, and two structurally identical credential slots.
- Each credential slot contains a random salt, fixed Argon2id profile metadata, one random nonce, and a fixed-length AEAD ciphertext wrapping one 32-byte view root key. No labels, timestamps, view names, or wrapper types are present.
- Each view descriptor occupies one fixed-size record at a fixed public position. It is AEAD ciphertext under a key derived from that view's root key. It contains that view's encrypted manifest, its record-index map, and authenticated logical length.
- The remaining area consists only of fixed-size records. Records referenced by either view contain AEAD ciphertext; unallocated records contain cryptographically random bytes. No plaintext occupied/free marker or per-view record count is stored.
- The total file size is selected at creation and does not grow during updates. An update that cannot fit must fail without modifying the original. A larger capacity requires explicit export to a new archive and must be documented as creating a snapshot-visible operation.

### Key derivation and encryption constraints

- Each of the two view root keys is generated independently with a CSPRNG; credentials never directly encrypt content.
- Argon2id derives one KEK per password using independent 16-byte random salts and the existing bounded profile allowlist. Both slots always serialize the same profile and lengths.
- AEAD wraps each root key with AAD binding format version, public capacity, slot index, and the complete immutable public header fields. The exact encoding must be canonical and covered by test vectors.
- A reviewed, standard HKDF-SHA-256 implementation derives per-view manifest and per-record keys using distinct labels and indices. No key is reused between views, records, or purposes. Nonce generation and maximum invocation counts must be written as explicit invariants before coding.
- The public header is not authenticated globally. Each credential slot authenticates its own root key; each descriptor and data record authenticates its own contents and index. Parsers must reject any malformed length or index before allocating from attacker-controlled values.

### Read/write behavior

- Unlock tries only the selected credential slot. All failures, including wrong password, bad wrapped key, malformed descriptor and tampering, produce one generic error before any plaintext output path is created.
- After unlock, the authenticated descriptor provides a set of record indices. Every listed index must be in range, unique within that view, and authenticate with the expected view/index AAD. The two views may not reference the same physical record.
- Restore writes to staging files and commits only after the selected view has fully authenticated. The other view and its records are never modified by open or restore.
- Adding or replacing content allocates random unused record indices and atomically writes a new fixed-size file. Existing unreferenced records are overwritten with fresh random bytes in the new output. The original remains intact on any failure.
- This design does not protect against repeated snapshots, host artifacts, file-size comparison across exports, opened plaintext traces, timing/memory observation, or an attacker who knows the application. It must not be marketed as coercion-safe or as general plausible deniability.

### Local review questions that remain before implementation

1. Is the fixed descriptor placement and identical pair of credential slots sufficient for the narrowly stated single-copy container model, including a one-view baseline? The proposed baseline is exactly two valid views, so the claim must not imply otherwise.
2. What fixed record size, maximum capacity, and manifest size bounds allow safe parsing and bounded memory on supported Windows systems?
3. Which AEAD is already supported by the dependency set, and what nonce construction meets its per-key usage limits without random-collision ambiguity?
4. Can updates be made atomic on supported filesystems without leaving observable partial output or modifying the input file?
5. What property tests and fuzz limits demonstrate fail-closed behavior? Which claims remain assumptions rather than tests?

**Decision:** this is now a concrete candidate for local design review, not an approved cryptographic construction. Resolve the five questions, write byte-exact vectors and validate dependency primitives before implementing a v4 parser or writer.

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
