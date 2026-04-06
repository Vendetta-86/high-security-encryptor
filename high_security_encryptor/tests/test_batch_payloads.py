from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.batch_binding import BindingValidationError, extract_binding
from high_security_encryptor.batch_payloads import (
    PasswordRecord,
    create_manifest_payload,
    create_password_table_payload,
    create_template_payload,
    deserialize_manifest_payload,
    deserialize_password_table_payload,
    deserialize_template_payload,
    serialize_manifest_payload,
    serialize_password_table_payload,
    serialize_template_payload,
    validate_manifest_payload,
    validate_password_table_payload,
    validate_template_payload,
)


class BatchPayloadTests(unittest.TestCase):
    def test_manifest_payload_round_trip(self) -> None:
        payload = create_manifest_payload(["b.gcm", "a.gcm"], mode="bundle", batch_id="batch-1")

        loaded = deserialize_manifest_payload(serialize_manifest_payload(payload))

        self.assertEqual(loaded["kind"], "manifest")
        self.assertEqual(loaded["binding"]["batch_id"], "batch-1")

    def test_password_table_validation_accepts_matching_binding(self) -> None:
        payload, binding = create_password_table_payload(
            [PasswordRecord("a.txt", "a.txt.gcm", "pw")],
            ["a.txt.gcm"],
            batch_id="batch-1",
        )
        loaded = deserialize_password_table_payload(serialize_password_table_payload(payload))

        validate_password_table_payload(loaded, binding)

    def test_password_table_validation_rejects_cross_batch_payload(self) -> None:
        payload_a, binding_a = create_password_table_payload(
            [PasswordRecord("a.txt", "a.txt.gcm", "pw")],
            ["a.txt.gcm"],
            batch_id="batch-a",
        )
        payload_b, _binding_b = create_password_table_payload(
            [PasswordRecord("b.txt", "b.txt.gcm", "pw")],
            ["b.txt.gcm"],
            batch_id="batch-b",
        )
        loaded_b = deserialize_password_table_payload(serialize_password_table_payload(payload_b))

        with self.assertRaises(BindingValidationError):
            validate_password_table_payload(loaded_b, binding_a)

    def test_template_validation_rejects_cross_batch_payload(self) -> None:
        payload_a, binding_a = create_template_payload(["a.txt"], ["a.txt.gcm"], batch_id="batch-a")
        payload_b, _binding_b = create_template_payload(["b.txt"], ["b.txt.gcm"], batch_id="batch-b")
        loaded_b = deserialize_template_payload(serialize_template_payload(payload_b))

        with self.assertRaises(BindingValidationError):
            validate_template_payload(loaded_b, binding_a)

    def test_manifest_validation_rejects_cross_batch_payload(self) -> None:
        payload_a = create_manifest_payload(["a.txt.gcm"], mode="bundle", batch_id="batch-a")
        payload_b = create_manifest_payload(["b.txt.gcm"], mode="bundle", batch_id="batch-b")
        loaded_b = deserialize_manifest_payload(serialize_manifest_payload(payload_b))

        with self.assertRaises(BindingValidationError):
            validate_manifest_payload(loaded_b, extract_binding(payload_a))


if __name__ == "__main__":
    unittest.main()
