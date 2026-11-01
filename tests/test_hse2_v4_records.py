from __future__ import annotations

import random
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
            (0, 6, encoded),
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

    def test_deterministic_payload_length_round_trips_and_mutation_fuzz(self) -> None:
        generator = random.Random(0x48325634524543)
        root = bytes(range(32))
        lengths = (0, 1, 15, 16, 17, 255, 4096, V4_RECORD_PAYLOAD_SIZE)
        for sample, length in enumerate(lengths):
            with self.subTest(sample=sample, length=length):
                plaintext = generator.randbytes(length)
                slot, index = sample % 2, sample * 2 + sample % 2
                record = seal_v4_record(
                    view_root_key=root, slot=slot, index=index, plaintext=plaintext
                )
                encoded = record.to_bytes()
                self.assertEqual(len(encoded), V4_RECORD_SIZE)
                self.assertEqual(
                    open_v4_record(
                        view_root_key=root, slot=slot, index=index,
                        record=encoded, plaintext_length=length,
                    ),
                    plaintext,
                )
                for offset in (0, 16, 48, len(encoded) // 2, len(encoded) - 1):
                    mutated = bytearray(encoded)
                    mutated[offset] ^= 1 << (sample % 8)
                    with self.subTest(offset=offset), self.assertRaises(HSE2ModelError):
                        open_v4_record(
                            view_root_key=root, slot=slot, index=index,
                            record=bytes(mutated), plaintext_length=length,
                        )


if __name__ == "__main__":
    unittest.main()
