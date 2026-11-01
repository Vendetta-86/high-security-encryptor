# HSE2 Phase 8: alternate-view container proposal (review draft)

## Status and scope

**Status: design draft for independent review; not an approved construction.** This proposal explores an explicitly limited alternate-view feature in a new container version. It does not authorize changes to HSE2 v2/v3, implementation, or any claim of plausible deniability. The intended user-visible term is **alternate view**, not hidden volume or duress protection.

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

## Required independent review package

The external reviewer must receive the exact versioned wire proposal, reference parser/writer, threat model, test corpus, and a list of excluded claims. Review must cover:

- cryptographic construction and key hierarchy, domain separation, nonce generation, AEAD limits, and authentication coverage;
- distinguishability from public fields, ciphertext length, malformed inputs, errors, timing, backups, and repeated snapshots within the stated scope;
- parser safety, downgrade behavior, resource limits, atomic updates, and recovery after partial writes;
- independent implementation feasibility and a test vector format.

The review result must identify reviewer independence, reviewed commit/digest, findings, severity, and unresolved assumptions. An internal review or test-only reference implementation is not third-party review.

## Implementation gates

No production code until the external reviewer accepts the construction or all blocking findings are resolved and re-reviewed. After that gate, implementation must use a new format version and separate modules; v2/v3 readers must continue to reject it as unsupported. Required tests include positive and negative credential paths, tampering, truncation, field mutation, generic failure behavior, fuzzing, memory/time limits, interrupted updates, backup/restore, downgrade attempts, and independent cross-implementation vectors. These tests can find defects but cannot establish real-world deniability outside the stated model.

## Source basis and limitations

- NIST SP 800-38D specifies GCM and is under revision; the current format already imposes a per-key invocation bound for random 96-bit IVs. A new format must re-evaluate this bound against the chosen nonce construction and usage model: https://csrc.nist.gov/pubs/sp/800/38/d/final
- RFC 9106 specifies Argon2; it informs password KDF requirements but does not solve alternate-view indistinguishability: https://www.rfc-editor.org/rfc/rfc9106
- VeraCrypt's own hidden-volume guidance documents operational limits and host-system exposure. It is a product-specific reference, not evidence that this file-container design inherits VeraCrypt's properties: https://veracrypt.io/en/Security%20Requirements%20for%20Hidden%20Volumes.html

This draft is an internal design artifact, not an independent cryptographic certification.
