import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.cli import main
from high_security_encryptor.hse2 import (
    HSE2Header,
    PayloadLayout,
    attach_header_auth_tag,
    build_wrapper_from_kek,
    encrypt_manifest,
    encrypt_payload_chunk,
    generate_dek,
    generate_kek,
    generate_mek,
    write_hse2_container,
)


class HSE2CliInspectTests(unittest.TestCase):
    def test_hse2_inspect_reports_container_metadata_without_secret(self) -> None:
        dek = generate_dek()
        mek = generate_mek()
        wrapper = build_wrapper_from_kek(
            wrapper_id="keyfile-1",
            wrapper_type="keyfile",
            created_utc="2026-05-25T00:00:00Z",
            dek=dek,
            mek=mek,
            kek=generate_kek(),
            kdf_metadata={"algorithm": "test"},
        ).record
        manifest = encrypt_manifest({"entries": [{"name": "file.txt", "chunks": [0]}]}, mek=mek, context=b"cli-inspect")
        chunk = encrypt_payload_chunk(b"payload bytes", dek=dek, index=0, context=b"cli-inspect")
        header = attach_header_auth_tag(
            HSE2Header(
                created_utc="2026-05-25T00:00:00Z",
                payload_layout=PayloadLayout(chunk_count=1, payload_offset=2048, footer_offset=4096),
                wrappers=(wrapper,),
            ),
            mek=mek,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "archive.hse2"
            write_hse2_container(path, header=header, manifest=manifest, payload_chunks=(chunk,))
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["hse2-inspect", "--input", str(path)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "hse2-inspect")
            self.assertTrue(payload["experimental"])
            self.assertEqual(payload["format"], "HSE2")
            self.assertEqual(payload["format_version"], 2)
            self.assertEqual(payload["wrapper_count"], 1)
            self.assertEqual(payload["wrapper_types"], ["keyfile"])
            self.assertTrue(payload["has_header_auth_tag"])
            self.assertTrue(payload["has_manifest"])
            self.assertEqual(payload["payload_chunk_count"], 1)
            self.assertEqual(payload["payload_layout"]["chunk_count"], 1)


if __name__ == "__main__":
    unittest.main()
