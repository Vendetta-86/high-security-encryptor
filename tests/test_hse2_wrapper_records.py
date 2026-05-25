from __future__ import annotations

import unittest

from high_security_encryptor.hse2 import make_placeholder_wrapper
from high_security_encryptor.hse2.errors import HSE2FormatError
from high_security_encryptor.hse2.wrappers import (
    WRAPPER_DPAPI,
    WRAPPER_PASSWORD,
    WrapperRecord,
    WrappedKeys,
)


class HSE2WrapperRecordTests(unittest.TestCase):
    def test_wrapper_record_round_trip(self) -> None:
        wrapper = make_placeholder_wrapper(
            wrapper_id="password-1",
            wrapper_type=WRAPPER_PASSWORD,
            profile_name="compatible",
            label="test password",
        )

        restored = WrapperRecord.from_dict(wrapper.to_dict())

        self.assertEqual(restored.id, wrapper.id)
        self.assertEqual(restored.type, wrapper.type)
        self.assertEqual(restored.kdf.name, "compatible")
        self.assertEqual(restored.label, "test password")
        self.assertEqual(restored.wrapped_keys.dek, wrapper.wrapped_keys.dek)
        self.assertEqual(restored.wrapped_keys.mek, wrapper.wrapped_keys.mek)

    def test_dpapi_wrapper_does_not_require_kdf(self) -> None:
        wrapper = make_placeholder_wrapper(
            wrapper_id="dpapi-1",
            wrapper_type=WRAPPER_DPAPI,
        )

        wrapper.validate()
        restored = WrapperRecord.from_dict(wrapper.to_dict())

        self.assertIsNone(restored.kdf)
        self.assertEqual(restored.type, WRAPPER_DPAPI)

    def test_password_wrapper_requires_kdf(self) -> None:
        wrapper = WrapperRecord(
            id="password-1",
            type=WRAPPER_PASSWORD,
            kdf=None,
            nonce=b"0" * 12,
            wrapped_keys=WrappedKeys(dek=b"1" * 32, mek=b"2" * 32),
        )

        with self.assertRaises(HSE2FormatError):
            wrapper.validate()

    def test_invalid_wrapper_type_is_rejected(self) -> None:
        wrapper = WrapperRecord(
            id="bad-1",
            type="bad",
            kdf=None,
            nonce=b"0" * 12,
            wrapped_keys=WrappedKeys(dek=b"1" * 32, mek=b"2" * 32),
        )

        with self.assertRaises(HSE2FormatError):
            wrapper.validate()

    def test_invalid_base64_wrapped_key_is_rejected(self) -> None:
        data = {
            "id": "password-1",
            "type": WRAPPER_PASSWORD,
            "kdf": {"name": "hardened"},
            "nonce": "MDAwMDAwMDAwMDAw",
            "wrapped_keys": {"dek": "not valid base64!", "mek": "dGVzdA=="},
        }

        with self.assertRaises(HSE2FormatError):
            WrapperRecord.from_dict(data)


if __name__ == "__main__":
    unittest.main()
