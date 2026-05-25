import json
import unittest

from high_security_encryptor.hse2 import (
    HSE2Header,
    HSE2ModelError,
    ManifestPolicy,
    WrappedKeys,
    WrapperRecord,
    canonical_json_bytes,
    get_kdf_profile,
)


class HSE2ModelTests(unittest.TestCase):
    def test_kdf_profiles_match_frozen_parameters(self) -> None:
        compatible = get_kdf_profile("compatible")
        hardened = get_kdf_profile("hardened")
        paranoid = get_kdf_profile("paranoid")

        self.assertEqual(compatible.memory_cost_kib, 65536)
        self.assertEqual(compatible.time_cost, 3)
        self.assertEqual(compatible.parallelism, 4)

        self.assertEqual(hardened.memory_cost_kib, 262144)
        self.assertEqual(hardened.time_cost, 3)
        self.assertEqual(hardened.parallelism, 4)

        self.assertEqual(paranoid.memory_cost_kib, 1048576)
        self.assertEqual(paranoid.time_cost, 4)
        self.assertEqual(paranoid.parallelism, 4)

    def test_unknown_kdf_profile_is_rejected(self) -> None:
        with self.assertRaises(HSE2ModelError):
            get_kdf_profile("fast")

    def test_canonical_json_bytes_are_deterministic(self) -> None:
        first = {"b": 2, "a": {"d": 4, "c": 3}}
        second = {"a": {"c": 3, "d": 4}, "b": 2}

        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(canonical_json_bytes(first), b'{"a":{"c":3,"d":4},"b":2}')

    def test_password_wrapper_requires_kdf_metadata(self) -> None:
        with self.assertRaises(HSE2ModelError):
            WrapperRecord(
                id="password-1",
                type="password",
                created_utc="2026-05-25T00:00:00Z",
                nonce="bm9uY2U=",
                wrapped_keys=WrappedKeys(dek="ZGVr", mek="bWVr"),
                auth_tag="dGFn",
            )

    def test_wrapper_record_serializes_optional_kdf(self) -> None:
        profile = get_kdf_profile("hardened")
        wrapper = WrapperRecord(
            id="password-1",
            type="password",
            label="main password",
            created_utc="2026-05-25T00:00:00Z",
            nonce="bm9uY2U=",
            wrapped_keys=WrappedKeys(dek="ZGVr", mek="bWVr"),
            auth_tag="dGFn",
            kdf=profile.to_dict(salt="c2FsdA=="),
        )

        data = wrapper.to_dict()

        self.assertEqual(data["id"], "password-1")
        self.assertEqual(data["type"], "password")
        self.assertEqual(data["label"], "main password")
        self.assertEqual(data["kdf"]["profile"], "hardened")
        self.assertEqual(data["wrapped_keys"], {"dek": "ZGVr", "mek": "bWVr"})

    def test_manifest_policy_rejects_inconsistent_encryption_policy(self) -> None:
        with self.assertRaises(HSE2ModelError):
            ManifestPolicy(encrypted=False, filename_policy="encrypted")

    def test_header_canonical_bytes_can_exclude_auth_tag(self) -> None:
        profile = get_kdf_profile("hardened")
        wrapper = WrapperRecord(
            id="password-1",
            type="password",
            created_utc="2026-05-25T00:00:00Z",
            nonce="bm9uY2U=",
            wrapped_keys=WrappedKeys(dek="ZGVr", mek="bWVr"),
            auth_tag="dGFn",
            kdf=profile.to_dict(salt="c2FsdA=="),
        )
        header = HSE2Header(
            created_utc="2026-05-25T00:00:00Z",
            wrappers=(wrapper,),
            header_auth_tag="aGVhZGVyLXRhZw==",
        )

        with_tag = json.loads(header.canonical_bytes(include_auth_tag=True).decode("utf-8"))
        without_tag = json.loads(header.canonical_bytes(include_auth_tag=False).decode("utf-8"))

        self.assertEqual(with_tag["header_auth"]["tag"], "aGVhZGVyLXRhZw==")
        self.assertNotIn("tag", without_tag["header_auth"])
        self.assertEqual(with_tag["wrappers"][0]["kdf"]["profile"], "hardened")


if __name__ == "__main__":
    unittest.main()
