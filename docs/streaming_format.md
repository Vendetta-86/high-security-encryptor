# Streaming Format Draft

## Goals

- avoid loading whole files into memory
- preserve authenticated encryption guarantees
- support forward-compatible versioning
- keep legacy-format detection possible

## Proposed container layout

Binary layout:

1. magic: 4 bytes, `HSE1`
2. version: 1 byte
3. flags: 1 byte
4. salt length: 1 byte
5. nonce length: 1 byte
6. chunk size: 4 bytes, big-endian
7. reserved: 4 bytes
8. salt
9. base nonce
10. chunk records
11. final manifest trailer

Each chunk record:

1. chunk index: 8 bytes
2. plaintext length: 4 bytes
3. tag: 16 bytes
4. ciphertext bytes

AAD:
- static header
- chunk index
- plaintext length

Nonce derivation:
- derive a per-file base nonce
- derive per-chunk nonce from `base_nonce XOR chunk_index`

Final trailer:
- total plaintext size
- total chunk count
- SHA-256 plaintext digest
- trailer tag authenticating summary metadata and digest

## Compatibility

- legacy files remain readable through old parser path
- new files use `HSE1`
- decryption dispatch is based on magic/version

## Security notes

- chunk tags prevent silent chunk substitution
- trailer prevents truncation/extension ambiguity
- plaintext digest binds the reconstructed whole-file content, not just chunk-local integrity
- legacy `GCM1` files are dispatched to a separate compatibility path
