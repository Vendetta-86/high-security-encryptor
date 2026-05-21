# HSE2 Streaming Helper Draft

This draft adds experimental HSE2 file-level streaming helpers without replacing
or modifying the existing HSE1 CLI path.

## Encryption Flow

1. Generate a random data-encryption key (DEK).
2. Generate a KDF salt and derive a key-encryption key (KEK) from the user
   password and the selected Argon2id profile.
3. Wrap the DEK with the KEK.
4. Build a self-describing HSE2 header containing KDF metadata, the wrapped DEK,
   the payload algorithm, the chunk size, and the base nonce.
5. Serialize the framed HSE2 header.
6. Build payload associated data from immutable payload metadata only.
7. Encrypt each payload chunk with the DEK using AES-GCM.
8. Bind each chunk and trailer to the immutable payload associated data.

## Decryption Flow

1. Read and parse the HSE2 header frame.
2. Derive the KEK from the password and header KDF metadata.
3. Unwrap the DEK.
4. Rebuild the immutable payload associated data from the header.
5. Authenticate and decrypt each payload chunk using that payload AAD.
6. Authenticate the trailer and verify chunk count, plaintext size, and plaintext
   digest.

## Payload AAD and Rewrap Compatibility

Payload AAD deliberately excludes mutable key-wrapping metadata:

- KDF profile;
- KDF salt;
- wrapped DEK nonce/ciphertext/tag.

Payload AAD includes metadata that must remain stable for existing payload bytes:

- HSE2 version;
- content algorithm;
- chunk size;
- base nonce;
- an explicit payload-AAD context string.

This allows future rewrap operations to replace the password-derived KEK, KDF
salt, KDF profile, and wrapped DEK without rewriting payload chunks. Changing
payload-affecting fields such as chunk size or base nonce still invalidates the
payload authentication context.

## Compatibility

The helpers are intentionally not wired into `encrypt-batch`, `decrypt-batch`, or
quick-use GUI flows yet. Existing HSE1 containers remain the default production
format.

## Current Scope

Implemented:

- file-level HSE2 encrypt/decrypt helpers;
- random DEK generation;
- password-derived KEK using HSE2 KDF metadata;
- wrapped DEK storage through the HSE2 header;
- rewrap-compatible payload AAD;
- payload-AAD-bound chunk and trailer authentication;
- round-trip and tamper tests.

Not implemented yet:

- CLI/GUI selection of HSE2;
- streaming output adapters equivalent to HSE1 `encrypted_output_stream`;
- rewrap command;
- keyfile or device-bound wrapping modes;
- migration tooling from HSE1 to HSE2.
