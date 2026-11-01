# Phase 1 Local Format Freeze Review

Date: 2026-11-01

## Scope

This review closes Phase 1 for the existing HSE2 v2/v3 wire formats. It is a local consistency review for this self-use project, not a third-party audit or a claim of cryptographic certification. The experimental v4 alternate-view proposal remains separate and does not change v2/v3.

## Cross-checks

- V2 source and reference agree on the 16-byte big-endian `>4sBBH Q` preamble, `HSE2` magic, version 2, canonical-JSON encoding marker 1, zero reserved field, and 64-bit header length.
- V3 source and reference agree on the same preamble width with version 3, canonical authenticated JSON header, 1 MiB header ceiling, 64 MiB manifest ceiling, 16 MiB chunk ceiling, 12-byte GCM nonces, and 16-byte tags.
- Header authentication context is `HSE2:header-auth:v1`; framing documentation specifies the authenticated canonical-header representation.
- Existing v2/v3 fixtures, v2 codec tests, v3 framing tests, and the local test-only v3 reference implementation exercise serialization, parsing, round-trip, mismatch, and tampering paths.
- HSE1 remains an explicit migration boundary; migration writes a new HSE2 output and leaves the input unchanged.
- Full suite on this review commit: 694 passed, 6 skipped. v4-targeted tests are recorded separately and are not evidence for v2/v3 format safety.

## Decision and limits

Phase 1 is complete for the frozen v2/v3 formats and their documented compatibility boundary. The project does not require third-party interoperability or independent review as a release gate. This local review does not establish third-party interoperability, resistance to unmodeled attacks, or safety of the separate v4 candidate.
