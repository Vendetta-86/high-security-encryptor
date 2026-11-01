from __future__ import annotations

import unittest

from high_security_encryptor.hse2.container_v4_crypto import V4_RECORD_SIZE
from high_security_encryptor.hse2.container_v4_records import (
    V4_RECORD_PAYLOAD_SIZE,
    V4Record,
    open_v4_record,
    seal_v4_record,
)
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4RecordTests(unittest.TestCase):
    def test_fixed_size_record_round_trip_and_empty_payload(self) -> None:
        root = bytes(range(32))
        payload = b"v4 record payload" * 31
        record = seal_v4_record(view_root_key=root, slot=1, index=17, plaintext=payload)
        encoded = record.to_bytes()
        self.assertEqual(len(encoded), V4_RECORD_SIZE)
        self.assertEqual(V4Record.from_bytes(encoded), record)
        self.assertEqual(
            open_v4_record(view_root_key=root, slot=1, index=17,
                           record=encoded, plaintext_length=len(payload)),
            payload,
        )
        empty = seal_v4_record(view_root_key=root, slot=0, index=0, plaintext=b"")
        self.assertEqual(
            open_v4_record(view_root_key=root, slot=0, index=0,
                           record=empty, plaintext_length=0),
            b"",
        )

    def test_record_authentication_binds_slot_index_and_bytes(self) -> None:
        root = bytes(range(32))
        record = seal_v4_record(view_root_key=root, slot=0, index=4, plaintext=b"data")
        encoded = record.to_bytes()
        for slot, index, changed in (
            (1, 4, encoded),
            (0, 5, encoded),
            (0, 4, encoded[:300] + bytes([encoded[300] ^ 1]) + encoded[301:]),
            (0, 4, encoded[:-1] + bytes([encoded[-1] ^ 1])),
        ):
            with self.subTest(slot=slot, index=index, tampered=changed != encoded):
                with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
                    open_v4_record(view_root_key=root, slot=slot, index=index,
                                   record=changed, plaintext_length=4)

    def test_record_rejects_unbounded_or_invalid_inputs(self) -> None:
        root = bytes(range(32))
        with self.assertRaises(HSE2ModelError):
            V4Record.from_bytes(b"short")
        with self.assertRaises(HSE2ModelError):
            seal_v4_record(view_root_key=root, slot=2, index=0, plaintext=b"")
        with self.assertRaises(HSE2ModelError):
            seal_v4_record(view_root_key=root, slot=0, index=0, plaintext=b"x" * (V4_RECORD_PAYLOAD_SIZE + 1))
        record = seal_v4_record(view_root_key=root, slot=0, index=0, plaintext=b"x")
        with self.assertRaises(HSE2ModelError):
            open_v4_record(view_root_key=root, slot=0, index=0, record=record,
                           plaintext_length=V4_RECORD_PAYLOAD_SIZE + 1)


if __name__ == "__main__":
    unittest.main()
