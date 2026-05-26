import sys
import unittest

from high_security_encryptor.hse2 import (
    HSE2ModelError,
    dpapi_protect_bytes,
    dpapi_unprotect_bytes,
    is_dpapi_available,
)


class HSE2DPAPITests(unittest.TestCase):
    def test_availability_matches_platform(self) -> None:
        self.assertEqual(is_dpapi_available(), sys.platform == "win32")

    def test_rejects_empty_input(self) -> None:
        with self.assertRaises(HSE2ModelError):
            dpapi_protect_bytes(b"")

    def test_rejects_non_bytes_input(self) -> None:
        with self.assertRaises(HSE2ModelError):
            dpapi_protect_bytes("not-bytes")  # type: ignore[arg-type]

    @unittest.skipUnless(sys.platform == "win32", "DPAPI is Windows-only")
    def test_round_trip_on_windows(self) -> None:
        plaintext = b"hse2 dpapi test bytes"
        entropy = b"hse2 test entropy"

        protected = dpapi_protect_bytes(plaintext, entropy=entropy)
        recovered = dpapi_unprotect_bytes(protected, entropy=entropy)

        self.assertNotEqual(protected, plaintext)
        self.assertEqual(recovered, plaintext)

    @unittest.skipIf(sys.platform == "win32", "non-Windows behavior only")
    def test_non_windows_rejects_dpapi_calls(self) -> None:
        with self.assertRaises(HSE2ModelError):
            dpapi_protect_bytes(b"hse2 bytes")
        with self.assertRaises(HSE2ModelError):
            dpapi_unprotect_bytes(b"hse2 bytes")


if __name__ == "__main__":
    unittest.main()
