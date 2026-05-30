import unittest

from high_security_encryptor.hse2 import (
    HSE2ModelError,
    HSE2UnlockFactors,
    build_keyfile_wrapper,
    build_password_keyfile_wrapper,
    build_password_wrapper,
    generate_dek,
    generate_mek,
    unlock_first_matching_wrapper,
    unlock_wrapper,
)

_TEST_FACTOR = "unlock-factor-alpha"
_WRONG_TEST_FACTOR = "unlock-factor-beta"


class HSE2UnlockTests(unittest.TestCase):
    def _keys(self):
        return generate_dek(), generate_mek()

    def test_unlock_password_wrapper(self) -> None:
        dek, mek = self._keys()
        built = build_password_wrapper(
            wrapper_id="password-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            password=_TEST_FACTOR,
            profile_name="compatible",
        )

        recovered = unlock_wrapper(built.record, factors=HSE2UnlockFactors(password=_TEST_FACTOR))

        self.assertEqual(recovered.dek, dek)
        self.assertEqual(recovered.mek, mek)

    def test_unlock_keyfile_wrapper(self) -> None:
        dek, mek = self._keys()
        keyfile = b"K" * 64
        built = build_keyfile_wrapper(
            wrapper_id="keyfile-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            keyfile_bytes=keyfile,
        )

        recovered = unlock_wrapper(built.record, factors=HSE2UnlockFactors(keyfile_bytes=keyfile))

        self.assertEqual(recovered.dek, dek)
        self.assertEqual(recovered.mek, mek)

    def test_unlock_password_keyfile_wrapper(self) -> None:
        dek, mek = self._keys()
        keyfile = b"K" * 64
        built = build_password_keyfile_wrapper(
            wrapper_id="password-keyfile-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            password=_TEST_FACTOR,
            keyfile_bytes=keyfile,
            profile_name="compatible",
        )

        recovered = unlock_wrapper(
            built.record,
            factors=HSE2UnlockFactors(password=_TEST_FACTOR, keyfile_bytes=keyfile),
        )

        self.assertEqual(recovered.dek, dek)
        self.assertEqual(recovered.mek, mek)

    def test_unlock_password_wrapper_requires_password_factor(self) -> None:
        dek, mek = self._keys()
        built = build_password_wrapper(
            wrapper_id="password-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            password=_TEST_FACTOR,
            profile_name="compatible",
        )

        with self.assertRaises(HSE2ModelError):
            unlock_wrapper(built.record, factors=HSE2UnlockFactors())

    def test_unlock_first_matching_wrapper_skips_incompatible_wrappers(self) -> None:
        dek, mek = self._keys()
        keyfile = b"K" * 64
        password_wrapper = build_password_wrapper(
            wrapper_id="password-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            password=_TEST_FACTOR,
            profile_name="compatible",
        ).record
        keyfile_wrapper = build_keyfile_wrapper(
            wrapper_id="keyfile-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            keyfile_bytes=keyfile,
        ).record

        recovered = unlock_first_matching_wrapper((password_wrapper, keyfile_wrapper), factors=HSE2UnlockFactors(keyfile_bytes=keyfile))

        self.assertEqual(recovered.dek, dek)
        self.assertEqual(recovered.mek, mek)

    def test_unlock_first_matching_wrapper_rejects_wrong_factor(self) -> None:
        dek, mek = self._keys()
        built = build_password_wrapper(
            wrapper_id="password-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            password=_TEST_FACTOR,
            profile_name="compatible",
        )

        with self.assertRaises(HSE2ModelError):
            unlock_first_matching_wrapper((built.record,), factors=HSE2UnlockFactors(password=_WRONG_TEST_FACTOR))

    def test_unlock_first_matching_wrapper_rejects_no_compatible_factor(self) -> None:
        dek, mek = self._keys()
        built = build_keyfile_wrapper(
            wrapper_id="keyfile-1",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            keyfile_bytes=b"K" * 64,
        )

        with self.assertRaises(HSE2ModelError):
            unlock_first_matching_wrapper((built.record,), factors=HSE2UnlockFactors(password=_TEST_FACTOR))


if __name__ == "__main__":
    unittest.main()
