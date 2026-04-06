from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.batch_binding import (
    BindingValidationError,
    attach_binding,
    build_manifest_fingerprint,
    create_batch_binding,
    extract_binding,
    validate_binding,
)


class BatchBindingTests(unittest.TestCase):
    def test_binding_round_trip(self) -> None:
        binding = create_batch_binding(["b/file.gcm", "a/file.gcm"], batch_id="batch-1")
        payload = attach_binding({"kind": "manifest"}, binding)

        extracted = extract_binding(payload)

        self.assertEqual(extracted.batch_id, "batch-1")
        self.assertEqual(extracted.file_count, 2)
        self.assertEqual(extracted.manifest_fingerprint, build_manifest_fingerprint(["a/file.gcm", "b/file.gcm"]))

    def test_validate_binding_accepts_matching_payload(self) -> None:
        binding = create_batch_binding(["a.gcm", "b.gcm"], batch_id="batch-1")
        payload = attach_binding({"kind": "password_table"}, binding)

        validate_binding(binding, payload)

    def test_validate_binding_rejects_mismatched_batch_id(self) -> None:
        expected = create_batch_binding(["a.gcm", "b.gcm"], batch_id="batch-1")
        actual = create_batch_binding(["a.gcm", "b.gcm"], batch_id="batch-2")
        payload = attach_binding({"kind": "password_table"}, actual)

        with self.assertRaises(BindingValidationError):
            validate_binding(expected, payload)

    def test_validate_binding_rejects_mismatched_fingerprint(self) -> None:
        expected = create_batch_binding(["a.gcm", "b.gcm"], batch_id="batch-1")
        actual = create_batch_binding(["a.gcm", "c.gcm"], batch_id="batch-1")
        payload = attach_binding({"kind": "password_table"}, actual)

        with self.assertRaises(BindingValidationError):
            validate_binding(expected, payload)


if __name__ == "__main__":
    unittest.main()
