# HSE2 Rewrap Helper Draft

This draft adds an experimental file-level rewrap helper for HSE2 containers.
It is not wired into CLI or GUI workflows yet.

## Purpose

Rewrap changes the key-encryption layer without rewriting encrypted payload
chunks. It is used to support future workflows such as:

- changing a container password;
- upgrading the KDF profile;
- rotating KDF salt;
- preparing for keyfile or device-bound wrappers.

## Flow

1. Read the existing HSE2 header.
2. Derive the current wrapper key from the supplied existing secret and header
   KDF metadata.
3. Unwrap the existing DEK.
4. Derive a new wrapper key from the replacement secret and new KDF metadata.
5. Wrap the same DEK with the new wrapper key.
6. Build a replacement header that preserves immutable payload metadata.
7. Verify the replacement header has the same payload AAD as the original header.
8. Write the replacement header and copy existing payload bytes unchanged.

## Safety Invariant

The replacement header must preserve payload AAD. Rewrap may change:

- KDF profile;
- KDF salt;
- wrapped DEK nonce/ciphertext/tag.

Rewrap must not change:

- HSE2 version;
- content algorithm;
- chunk size;
- base nonce.

Changing payload-affecting fields would invalidate chunk and trailer
authentication tags, so the helper rejects any replacement header that changes
payload AAD.

## Current Scope

Implemented:

- read and authenticate the existing wrapper;
- build a replacement wrapped-DEK header;
- copy payload bytes unchanged;
- tests for successful rewrap, wrong old secret rejection, payload-byte
  preservation, and KDF profile upgrade.

Not implemented yet:

- CLI command;
- GUI flow;
- in-place rewrap;
- keyfile/device-bound wrappers;
- backup and rollback policy for production use.
