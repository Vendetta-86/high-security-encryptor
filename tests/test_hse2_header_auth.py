import unittest

from high_security_encryptor.hse2 import (
    HSE2Header,
    HSE2ModelError,
    PayloadLayout,
    attach_header_auth_tag,
    build_wrapper_from_kek,
    compute_header_auth_tag,
    generate_dek,
    generate_kek,
    generate_mek,
    require_valid_header_auth_tag,
    verify_header_auth_tag,
)


class HSE2HeaderAuthTests(unittest.TestCase):
    def _header(self) -> tuple[HSE2Header, object]:
        mek = generate_mek()
        wrapper = build_wrapper_from_kek(
            wrapper_id="keyfile-1",
            wrapper_type="keyfile",
            created_utc="2026-05-25T00:00:00Z",
            dek=generate_dek(),
            mek=mek,
            kek=generate_kek(),
            kdf_metadata={"algorithm": "test"},
        ).record
        header = HSE2Header(
            created_utc="2026-05-25T00:00:00Z",
            payload_layout=PayloadLayout(chunk_count=2, payload_offset=1024, footer_offset=4096),
            wrappers=(wrapper,),
        )
        return header, mek

    def test_header_auth_tag_is_deterministic(self) -> None:
        header, mek = self._header()

        first = compute_header_auth_tag(header, mek=mek)
        second = compute_header_auth_tag(header, mek=mek)

        self.assertEqual(first, second)

    def test_attach_and_verify_header_auth_tag(self) -> None:
        header, mek = self._header()

        authenticated = attach_header_auth_tag(header, mek=mek)

        self.assertIsNotNone(authenticated.header_auth_tag)
        self.assertTrue(verify_header_auth_tag(authenticated, mek=mek))
        require_valid_header_auth_tag(authenticated, mek=mek)

    def test_header_auth_rejects_tampered_header_field(self) -> None:
        header, mek = self._header()
        authenticated = attach_header_auth_tag(header, mek=mek)
        tampered = HSE2Header(
            created_utc=authenticated.created_utc,
            cipher_suite=authenticated.cipher_suite,
            manifest_policy=authenticated.manifest_policy,
            payload_layout=PayloadLayout(chunk_count=3, payload_offset=1024, footer_offset=4096),
            wrappers=authenticated.wrappers,
            format=authenticated.format,
            format_version=authenticated.format_version,
            header_auth_algorithm=authenticated.header_auth_algorithm,
            header_auth_tag=authenticated.header_auth_tag,
        )

        self.assertFalse(verify_header_auth_tag(tampered, mek=mek))
        with self.assertRaises(HSE2ModelError):
            require_valid_header_auth_tag(tampered, mek=mek)

    def test_header_auth_rejects_wrong_mek(self) -> None:
        header, mek = self._header()
        authenticated = attach_header_auth_tag(header, mek=mek)

        self.assertFalse(verify_header_auth_tag(authenticated, mek=generate_mek()))

    def test_header_auth_requires_mek(self) -> None:
        header, _ = self._header()

        with self.assertRaises(HSE2ModelError):
            compute_header_auth_tag(header, mek=generate_dek())

    def test_header_auth_requires_existing_tag_for_verification(self) -> None:
        header, mek = self._header()

        with self.assertRaises(HSE2ModelError):
            verify_header_auth_tag(header, mek=mek)


if __name__ == "__main__":
    unittest.main()
