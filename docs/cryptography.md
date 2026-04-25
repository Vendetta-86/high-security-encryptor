# Cryptography Notes

This repository currently uses AES-GCM with 256-bit keys, not AES-128.

## Summary

- `AES-128` uses a 16-byte key.
- `AES-256` uses a 32-byte key.
- The active code paths in this repository derive 32-byte AES keys, so the effective encryption level is `AES-256-GCM`.

## Current Implementations

### Streaming file encryption

The main `HSE1` streaming container uses a 32-byte AES key derived with Argon2id.

Relevant implementation:

- `src/high_security_encryptor/streaming_primitives.py`
  - `KEY_LEN = 32`
  - `hash_len=KEY_LEN`

### Metadata encryption

Encrypted metadata sidecars also use a 32-byte AES key derived with Argon2id.

Relevant implementation:

- `src/high_security_encryptor/metadata_crypto.py`
  - `KEY_LEN = 32`
  - `hash_len=KEY_LEN`

### Legacy `GCM1` compatibility path

The legacy decryption compatibility path still uses a 32-byte AES key, so legacy `GCM1` files handled by this repository are also `AES-256-GCM`, not `AES-128-GCM`.

Relevant implementation:

- `src/high_security_encryptor/legacy.py`
  - `LEGACY_KEY_LEN = 32`
  - `hash_len=LEGACY_KEY_LEN`

### Standalone merged script

The root-level standalone script `aes_gcm_merged_final.py` also derives a 32-byte AES key and uses AES-GCM.

Relevant implementation:

- `aes_gcm_merged_final.py`
  - `KEY_LEN = 32`
  - `hash_len=KEY_LEN`

## Other AES-GCM Parameters

The current implementations use standard AES-GCM parameter sizes:

- nonce length: 12 bytes
- authentication tag length: 16 bytes

## Key Derivation

The repository derives AES keys from passwords with Argon2id instead of using raw passwords directly.

Current Argon2id parameters used in the AES-GCM paths:

- time cost: `3`
- memory cost: `65536` KiB
- parallelism: `4`

These parameters affect password hardening. They do not change AES from 128-bit to 256-bit; the AES level is determined by the derived key length.
