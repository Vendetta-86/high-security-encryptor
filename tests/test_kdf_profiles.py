"""Tests for Argon2id KDF profile helpers."""

from __future__ import annotations

import unittest

from argon2.low_level import Type, hash_secret_raw

from high_security_encryptor.kdf_profiles import (
    KEY_LEN,
    KDF_PROFILE_COMPATIBLE,
    KDF_PROFILE_HARDENED,
    KDF_PROFILE_PARANOID,
    derive_argon2id_key,
    get_kdf_profile,
)
from high_security_encryptor.streaming_primitives import (
    ARGON_MEMORY_COST,
    ARGON_PARALLELISM,
    ARGON_TIME_COST,
    derive_key,
)


class KdfProfileTests(unittest.TestCase):
    def test_compatible_profile_preserves_hse1_parameters(self) -> None:
        profile = get_kdf_profile(KDF_PROFILE_COMPATIBLE)

        self.assertEqual(profile.time_cost, ARGON_TIME_COST)
        self.assertEqual(profile.memory_cost_kib, ARGON_MEMORY_COST)
        self.assertEqual(profile.parallelism, ARGON_PARALLELISM)
        self.assertEqual(profile.hash_len, KEY_LEN)

    def test_hse1_derive_key_matches_historical_argon2id_parameters(self) -> None:
        sample_phrase = "unit test phrase only"
        sample_salt = b"hse-test-salt-000"

        expected = hash_secret_raw(
            secret=sample_phrase.encode("utf-8"),
            salt=sample_salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=KEY_LEN,
            type=Type.ID,
        )

        self.assertEqual(derive_key(sample_phrase, sample_salt), expected)

    def test_profiles_are_ordered_by_memory_hardness(self) -> None:
        compatible = get_kdf_profile(KDF_PROFILE_COMPATIBLE)
        hardened = get_kdf_profile(KDF_PROFILE_HARDENED)
        paranoid = get_kdf_profile(KDF_PROFILE_PARANOID)

        self.assertLess(compatible.memory_cost_kib, hardened.memory_cost_kib)
        self.assertLess(hardened.memory_cost_kib, paranoid.memory_cost_kib)
        self.assertGreaterEqual(paranoid.time_cost, hardened.time_cost)

    def test_profile_serialization_is_self_describing(self) -> None:
        payload = get_kdf_profile(KDF_PROFILE_HARDENED).as_dict()

        self.assertEqual(payload["algorithm"], "argon2id")
        self.assertEqual(payload["profile"], KDF_PROFILE_HARDENED)
        self.assertIn("memory_cost_kib", payload)
        self.assertIn("time_cost", payload)
        self.assertIn("parallelism", payload)

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            get_kdf_profile("unknown")

    def test_secret_phrase_and_salt_are_required(self) -> None:
        with self.assertRaises(ValueError):
            derive_argon2id_key("", b"hse-test-salt-000")
        with self.assertRaises(ValueError):
            derive_argon2id_key("unit test phrase only", b"")


if __name__ == "__main__":
    unittest.main()
