from __future__ import annotations

import unittest

from high_security_encryptor.hse2 import (
    HSE2Header,
    dumps_canonical_header,
    loads_canonical_header,
    make_placeholder_wrapper,
)
from high_security_encryptor.hse2.errors import HSE2FormatError
from high_security_encryptor.hse2.wrappers import WRAPPER_KEYFILE, WRAPPER_PASSWORD


class HSE2ContainerHeaderTests(unittest.TestCase):
    def test_header_round_trip_is_stable(self) -> None:
        wrapper = make_placeholder_wrapper(
            wrapper_id="password-1",
            wrapper_type=WRAPPER_PASSWORD,
            profile_name="hardened",
            label="main password",
        )
        header = HSE2Header(wrappers=(wrapper,))

        encoded = dumps_canonical_header(header)
        decoded = loads_canonical_header(encoded)
        encoded_again = dumps_canonical_header(decoded)

        self.assertEqual(encoded, encoded_again)
        self.assertEqual(decoded.format_version, 2)
        self.assertEqual(len(decoded.wrappers), 1)
        self.assertEqual(decoded.wrappers[0].id, "password-1")
        self.assertEqual(decoded.wrappers[0].type, WRAPPER_PASSWORD)

    def test_header_rejects_duplicate_wrapper_ids(self) -> None:
        first = make_placeholder_wrapper(
            wrapper_id="duplicate",
            wrapper_type=WRAPPER_PASSWORD,
        )
        second = make_placeholder_wrapper(
            wrapper_id="duplicate",
            wrapper_type=WRAPPER_KEYFILE,
        )
        header = HSE2Header(wrappers=(first, second))

        with self.assertRaises(HSE2FormatError):
            dumps_canonical_header(header)

    def test_header_rejects_wrong_format_marker(self) -> None:
        with self.assertRaises(HSE2FormatError):
            loads_canonical_header(b'{"format":"HSE1","format_version":2}')

    def test_header_rejects_wrong_version(self) -> None:
        with self.assertRaises(HSE2FormatError):
            loads_canonical_header(b'{"format":"HSE2","format_version":99}')

    def test_header_rejects_non_json(self) -> None:
        with self.assertRaises(HSE2FormatError):
            loads_canonical_header(b"not json")


if __name__ == "__main__":
    unittest.main()
