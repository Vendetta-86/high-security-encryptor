# KDF Profiles and Offline Resistance

This document describes the KDF profile layer used as the foundation for future
self-describing encrypted container formats.

## Current HSE1 Compatibility

HSE1 uses Argon2id with fixed parameters:

- `time_cost`: 3
- `memory_cost_kib`: 65536
- `parallelism`: 4
- `hash_len`: 32

These values are now represented by the `compatible` KDF profile. HSE1 still does
not serialize KDF parameters in its header, so these values must remain stable for
HSE1 decryption compatibility.

## Named Profiles

The profile layer currently defines three named profiles:

| Profile | Purpose | Memory |
| --- | --- | --- |
| `compatible` | HSE1 compatibility | 64 MiB |
| `hardened` | Future high-security default | 256 MiB |
| `paranoid` | Future high-value archive mode | 1 GiB |

The `hardened` and `paranoid` profiles are intended for future self-describing
formats such as HSE2. They should not be applied to HSE1 files because HSE1 has no
header fields for KDF parameter negotiation.

## HSE2 Direction

A future HSE2 container should serialize KDF metadata in the authenticated header,
for example:

```json
{
  "kdf": {
    "algorithm": "argon2id",
    "profile": "hardened",
    "time_cost": 3,
    "memory_cost_kib": 262144,
    "parallelism": 4,
    "hash_len": 32,
    "salt": "..."
  }
}
```

This enables:

- changing KDF parameters without breaking old files;
- adding calibrated per-machine parameters;
- rewrapping file data keys without rewriting large ciphertext payloads;
- supporting password plus keyfile or hardware-bound wrapping modes.

## Threat Model Notes

KDF profiles increase the cost of each offline password guess. They do not by
themselves prevent offline attacks when an attacker has all encrypted artifacts
and can test candidate passwords independently.

Stronger offline resistance should combine KDF profiles with at least one of:

- random data-encryption keys wrapped by password-derived keys;
- keyfiles or external pepper material not stored beside the ciphertext;
- Windows DPAPI/TPM-backed local wrapping modes;
- encrypted metadata and minimized unauthenticated plaintext headers.
