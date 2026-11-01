from __future__ import annotations

import unittest

from high_security_encryptor.hse2.container_v4_crypto import (
    V4Sealed,
    derive_v4_key,
    open_v4,
    seal_v4,
)
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4CryptoTests(unittest.TestCase):
    def test_hkdf_and_gcm_vector(self) -> None:
        root = bytes(range(32))
        salt = bytes(range(32, 64))
        info = b"HSE2:v4:view:0:record-wrap:7:v1"
        aad = b"HSE2:v4:slot:0:index:7:size:1048576"
        plaintext = bytes(range(32))
        key = derive_v4_key(root_key=root, salt=salt, info=info)
        self.assertEqual(
            key.hex(),
            "1f357c1b5768c99fd7d2211a92193393d8e02c80cd246ce4e9f34e0b6c55c0fe",  # pragma: allowlist secret
        )
        sealed = seal_v4(key=key, nonce=bytes(12), plaintext=plaintext, aad=aad)
        self.assertEqual(
            sealed.ciphertext.hex(),
            "9fc1f749c79556f60a2d490714566a538a72dadeb61517ab9aa26ea86667dbbb",  # pragma: allowlist secret
        )
        self.assertEqual(sealed.tag.hex(), "761fa63653ab7d9d2595ad795da3c149")  # pragma: allowlist secret
        self.assertEqual(open_v4(key=key, sealed=sealed, aad=aad), plaintext)

    def test_gcm_rejects_changed_aad_and_ciphertext(self) -> None:
        key = bytes(range(32))
        sealed = seal_v4(key=key, nonce=bytes(12), plaintext=b"payload", aad=b"context")
        with self.assertRaises(HSE2ModelError):
            open_v4(key=key, sealed=sealed, aad=b"other-context")
        changed = V4Sealed(
            nonce=sealed.nonce,
            ciphertext=bytes([sealed.ciphertext[0] ^ 1]) + sealed.ciphertext[1:],
            tag=sealed.tag,
        )
        with self.assertRaises(HSE2ModelError):
            open_v4(key=key, sealed=changed, aad=b"context")

    def test_hkdf_rejects_invalid_parameters(self) -> None:
        with self.assertRaises(HSE2ModelError):
            derive_v4_key(root_key=b"short", salt=bytes(32), info=b"info")
        with self.assertRaises(HSE2ModelError):
            derive_v4_key(root_key=bytes(32), salt=b"short", info=b"info")


if __name__ == "__main__":
    unittest.main()
