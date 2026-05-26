import unittest

from high_security_encryptor.hse2 import (
    HSE2_MAGIC,
    HSE2_PREAMBLE_SIZE,
    HSE2ModelError,
    HSE2Preamble,
    PayloadLayout,
    attach_header_auth_tag,
    build_wrapper_from_kek,
    decode_header_frame,
    encode_header_frame,
    generate_dek,
    generate_kek,
    generate_mek,
    require_valid_header_auth_tag,
    HSE2Header,
)


class HSE2ContainerCodecTests(unittest.TestCase):
    def _authenticated_header(self) -> tuple[HSE2Header, object]:
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
            payload_layout=PayloadLayout(chunk_count=1, payload_offset=2048, footer_offset=4096),
            wrappers=(wrapper,),
        )
        return attach_header_auth_tag(header, mek=mek), mek

    def test_preamble_round_trips(self) -> None:
        preamble = HSE2Preamble(header_length=1234)

        recovered = HSE2Preamble.from_bytes(preamble.to_bytes())

        self.assertEqual(recovered, preamble)
        self.assertEqual(len(preamble.to_bytes()), HSE2_PREAMBLE_SIZE)

    def test_header_frame_round_trips_and_preserves_trailing_bytes(self) -> None:
        header, mek = self._authenticated_header()
        trailing = b"encrypted-manifest-and-payload"

        preamble, recovered, remaining = decode_header_frame(encode_header_frame(header) + trailing)

        self.assertEqual(preamble.magic, HSE2_MAGIC)
        self.assertEqual(remaining, trailing)
        self.assertEqual(recovered.to_dict(), header.to_dict())
        require_valid_header_auth_tag(recovered, mek=mek)

    def test_decode_rejects_short_preamble(self) -> None:
        with self.assertRaises(HSE2ModelError):
            decode_header_frame(b"HSE")

    def test_decode_rejects_truncated_header(self) -> None:
        header, _ = self._authenticated_header()
        frame = encode_header_frame(header)

        with self.assertRaises(HSE2ModelError):
            decode_header_frame(frame[:-1])

    def test_preamble_rejects_invalid_magic(self) -> None:
        preamble = bytearray(HSE2Preamble(header_length=1).to_bytes())
        preamble[0:4] = b"BAD!"

        with self.assertRaises(HSE2ModelError):
            HSE2Preamble.from_bytes(bytes(preamble))

    def test_preamble_rejects_nonzero_reserved_field(self) -> None:
        preamble = bytearray(HSE2Preamble(header_length=1).to_bytes())
        preamble[6:8] = b"\x00\x01"

        with self.assertRaises(HSE2ModelError):
            HSE2Preamble.from_bytes(bytes(preamble))

    def test_decode_rejects_invalid_header_json(self) -> None:
        preamble = HSE2Preamble(header_length=len(b"not-json")).to_bytes()

        with self.assertRaises(HSE2ModelError):
            decode_header_frame(preamble + b"not-json")

    def test_decode_rejects_invalid_header_shape(self) -> None:
        preamble = HSE2Preamble(header_length=len(b"[]")).to_bytes()

        with self.assertRaises(HSE2ModelError):
            decode_header_frame(preamble + b"[]")


if __name__ == "__main__":
    unittest.main()
