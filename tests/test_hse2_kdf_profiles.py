from __future__ import annotations

import unittest

from high_security_encryptor.hse2 import get_kdf_profile
from high_security_encryptor.hse2.constants import (
    PROFILE_COMPATIBLE,
    PROFILE_HARDENED,
    PROFILE_PARANOID,
    SUPPORTED_KDF_ALGORITHM,
)
from high_security_encryptor.hse2.errors import HSE2UnsupportedProfileError


class HSE2KdfProfileTests(unittest.TestCase):
    def test_supported_profiles_are_argon2id(self) -> None:
        for name in (PROFILE_COMPATIBLE, PROFILE_HARDENED, PROFILE_PARANOID):
            with self.subTest(profile=name):
                profile = get_kdf_profile(name)
                self.assertEqual(profile.algorithm, SUPPORTED_KDF_ALGORITHM)
                self.assertEqual(profile.hash_len, 32)
                self.assertGreater(profile.memory_cost_kib, 0)
                self.assertGreater(profile.time_cost, 0)
                self.assertGreater(profile.parallelism, 0)

    def test_hardened_is_stronger_than_compatible(self) -> None:
        compatible = get_kdf_profile(PROFILE_COMPATIBLE)
        hardened = get_kdf_profile(PROFILE_HARDENED)

        self.assertGreater(hardened.memory_cost_kib, compatible.memory_cost_kib)
        self.assertGreaterEqual(hardened.time_cost, compatible.time_cost)

    def test_paranoid_is_stronger_than_hardened(self) -> None:
        hardened = get_kdf_profile(PROFILE_HARDENED)
        paranoid = get_kdf_profile(PROFILE_PARANOID)

        self.assertGreater(paranoid.memory_cost_kib, hardened.memory_cost_kib)
        self.assertGreaterEqual(paranoid.time_cost, hardened.time_cost)

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaises(HSE2UnsupportedProfileError):
            get_kdf_profile("weak")


if __name__ == "__main__":
    unittest.main()
