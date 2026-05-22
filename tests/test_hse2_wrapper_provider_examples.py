"""Smoke tests for HSE2 wrapper provider example configs."""

from __future__ import annotations

from pathlib import Path
import unittest

from high_security_encryptor.hse2_config import HSE2EncryptConfig


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = PROJECT_ROOT / "examples"


class HSE2WrapperProviderExampleTests(unittest.TestCase):
    def test_hse2_wrapper_provider_encrypt_examples_parse(self) -> None:
        example_names = [
            "hse2_literal_encrypt.testing.json",
            "hse2_env_encrypt.json",
            "hse2_file_encrypt.json",
            "hse2_keyfile_encrypt.json",
            "hse2_dpapi_encrypt.json",
        ]

        for name in example_names:
            with self.subTest(name=name):
                config = HSE2EncryptConfig.from_json_file(EXAMPLES_DIR / name)
                self.assertEqual(config.input, "plain.bin")
                self.assertEqual(config.output, "cipher.hse2")
                self.assertIn(config.kdf_profile, {"compatible", "hardened", "paranoid"})
                self.assertGreater(config.chunk_size, 0)
                self.assertIsInstance(config.wrapper, dict)
                self.assertIn("type", config.wrapper)


if __name__ == "__main__":
    unittest.main()
