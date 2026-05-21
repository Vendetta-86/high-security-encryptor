# HSE2 Header Draft

HSE2 is planned as a self-describing encrypted container format. This draft
captures the metadata that must be authenticated before payload chunks are
accepted.

## Frame Layout

The header frame is:

```text
4 bytes   magic: HSE2
4 bytes   big-endian JSON length
N bytes   canonical UTF-8 JSON header
```

The JSON payload is serialized with sorted keys and compact separators so the
same logical header has stable bytes for AEAD associated data.

## Header Fields

The current draft header includes:

- `version`: HSE2 format version.
- `content_algorithm`: payload encryption algorithm identifier.
- `chunk_size`: streaming payload chunk size.
- `base_nonce_hex`: base nonce used to derive chunk nonces.
- `kdf`: Argon2id profile metadata plus salt.
- `wrapped_data_key`: serialized wrapped DEK payload.

## Authentication Model

The complete framed header bytes are intended to be used as AEAD associated data
for later HSE2 payload encryption/decryption. This binds ciphertext chunks and
wrapped data keys to the exact header metadata.

The header parser rejects:

- invalid magic;
- malformed or oversized JSON;
- unsupported version or algorithms;
- KDF profile parameters that do not match the named profile;
- invalid nonce, salt, or wrapped-key lengths;
- trailing bytes when a complete frame is expected.

## Compatibility

This draft does not alter HSE1 and is not connected to CLI encryption or
decryption yet. HSE1 files remain handled by the existing HSE1 parser.

## Next Steps

- Add HSE2 streaming encryption/decryption helpers using random DEKs.
- Bind payload chunks to the framed header as AAD.
- Add rewrap support that replaces `wrapped_data_key` and KDF metadata without
  rewriting payload chunks.
- Add optional keyfile and device-bound wrapping modes.
