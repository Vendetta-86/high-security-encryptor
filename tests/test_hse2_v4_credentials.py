from __future__ import annotations

import unittest

from high_security_encryptor.hse2.container_v4_credentials import (
    V4_CREDENTIAL_SLOT_SIZE,
    V4CredentialSlot,
    create_v4_credentials,
    unlock_v4_credentials,
)
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V4CredentialTests(unittest.TestCase):
    def test_two_fixed_slots_unlock_exactly_their_assigned_roots(self) -> None:
        passwords = ("alpha view password", "beta view password")
        slots, roots = create_v4_credentials(*passwords, capacity_records=8)
        self.assertEqual(len(slots[0].to_bytes()), V4_CREDENTIAL_SLOT_SIZE)
        self.assertEqual(len(slots[1].to_bytes()), V4_CREDENTIAL_SLOT_SIZE)
        self.assertEqual(len(slots[0].to_bytes()), len(slots[1].to_bytes()))
        self.assertEqual(V4CredentialSlot.from_bytes(slots[0].to_bytes()), slots[0])
        self.assertEqual(unlock_v4_credentials(passwords[0], slots, capacity_records=8), (0, roots[0]))
        self.assertEqual(unlock_v4_credentials(passwords[1], slots, capacity_records=8), (1, roots[1]))

    def test_wrong_password_slot_reordering_and_capacity_fail_generically(self) -> None:
        slots, _ = create_v4_credentials("first secret", "second secret", capacity_records=2)
        for password, ordered_slots, capacity in (
            ("wrong secret", slots, 2),
            ("first secret", (slots[1], slots[0]), 2),
            ("first secret", slots, 4),
        ):
            with self.subTest(password=password, capacity=capacity):
                with self.assertRaisesRegex(HSE2ModelError, "authentication failed"):
                    unlock_v4_credentials(password, ordered_slots, capacity_records=capacity)

    def test_invalid_shapes_and_duplicate_passwords_are_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            V4CredentialSlot.from_bytes(b"short")
        with self.assertRaises(HSE2ModelError):
            create_v4_credentials("same", "same", capacity_records=2)
        with self.assertRaises(HSE2ModelError):
            create_v4_credentials("one", "two", capacity_records=2, profile_name="paranoid")


if __name__ == "__main__":
    unittest.main()
