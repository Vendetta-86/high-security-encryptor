# HSE2 Format Documentation Status

Date: 2026-06-20

## Result

`docs/hse2_format.md` already exists on `master` and covers the initial HSE2 format direction. This status note records the documentation state so Phase 1 tracking can treat the format-documentation item as present, while keeping the remaining format-freeze work explicit.

## Existing documentation coverage

`docs/hse2_format.md` currently documents:

- HSE2 goals and non-goals;
- threat model boundaries for offline ciphertext attacks;
- high-level container layout;
- fixed preamble requirements;
- authenticated header shape;
- DEK / MEK / KEK key model;
- wrapper record shape and supported initial wrapper types;
- Argon2id KDF profiles;
- encrypted manifest expectations;
- header backup boundaries;
- explicit access-destruction rules;
- deferred duress / decoy support;
- guarded create/open CLI staging;
- non-leaky error behavior.

## Current implementation alignment

The current alpha implementation is aligned with the format document at the following boundaries:

- HSE2 magic is `HSE2`.
- HSE2 format version is `2`.
- Header encoding is canonical JSON.
- Header authentication uses `HMAC-SHA256` over canonical header bytes with the header auth tag omitted.
- Supported wrapper types are `password`, `keyfile`, `password_keyfile`, and `dpapi`.
- Payload, manifest, and wrapper ciphers are `AES-256-GCM`.
- Initial KDF profiles are `compatible`, `hardened`, and `paranoid`.
- The manifest is encrypted by default in the archive create workflow.
- Archive create/open, header backup, wrapper list/remove, access destroy, and HSE2 GUI flows have reached alpha-level CLI/GUI coverage.

## Remaining Phase 1 work

The format documentation item itself should be considered present. Remaining Phase 1 work should focus on:

- tightening the distinction between implemented alpha behavior and future format-freeze commitments;
- documenting HSE1 compatibility and migration boundaries;
- documenting exact binary/JSON framing details in a stricter reference section if the project moves from alpha to stable format freeze;
- ensuring future changes do not silently alter on-disk HSE2 compatibility.

## Status

Phase 1 should no longer track `docs/hse2_format.md` as missing. The broader HSE2 format-freeze phase remains partially open until compatibility and stable-format commitments are finalized.
