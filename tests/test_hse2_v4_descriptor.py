from __future__ import annotations

import unittest

from high_security_encryptor.hse2.container_v4_crypto import V4_DESCRIPTOR_SIZE
from high_security_encryptor.hse2.container_v4_descriptor import (
    V4ViewDescriptor,
    open_v4_descriptor,
    seal_v4_descriptor,
)
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4DescriptorTests(unittest.TestCase):
    def test_fixed_size_descriptor_round_trip_and_authentication(self) -> None:
        root = bytes(range(32))
        view = V4ViewDescriptor(
            manifest={"files": [{"path": "a.txt", "size": 3}]},
            record_lengths={0: 3, 7: 1024},
        )
        region = seal_v4_descriptor(
            view_root_key=root, slot=0, capacity_records=8,
            manifest=view.manifest, record_lengths=view.record_lengths,
        )
        self.assertEqual(len(region), V4_DESCRIPTOR_SIZE)
        self.assertEqual(
            open_v4_descriptor(view_root_key=root, slot=0, capacity_records=8, region=region),
            view,
        )
        damaged = region[:-1] + bytes([region[-1] ^ 1])
        with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
            open_v4_descriptor(view_root_key=root, slot=0, capacity_records=8, region=damaged)

    def test_descriptor_rejects_invalid_record_map(self) -> None:
        with self.assertRaises(HSE2ModelError):
            seal_v4_descriptor(
                view_root_key=bytes(range(32)), slot=1, capacity_records=2,
                manifest={}, record_lengths={2: 1},
            )


if __name__ == "__main__":
    unittest.main()
