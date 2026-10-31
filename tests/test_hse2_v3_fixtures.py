from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
import tempfile
import unittest

from high_security_encryptor.hse2.workflows import open_hse2_archive
from high_security_encryptor.hse2.container_codec import decode_header_frame
from high_security_encryptor.hse2.container_stream import read_v3_header_frame


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "hse2"
FIXTURE_KEY = b"HSE2-FIXTURE-KEY-MATERIAL-000000"
FIXTURE_PAYLOAD = b"Codex HSE2 compatibility fixture v1\n"
FIXTURE_SHA256 = {
    "archive-v2.hse2": "44be3d3405f3b0bd4b0df01bd0493181440575505dc010ea91e13dbe1875f9b2",  # pragma: allowlist secret
    "archive-v3.hse2": "8676572a59a12cfc513dc4dd9a7a9c63fe867d4241dfc8ba3ff4fdc1a0b4c163",  # pragma: allowlist secret
}


class HSE2ArchiveFixtureTests(unittest.TestCase):
    def test_frozen_v2_and_v3_fixtures_keep_hashes_and_open(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            for version in (2, 3):
                name = f"archive-v{version}.hse2"
                archive = FIXTURE_DIR / name
                encoded = archive.read_bytes()
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), FIXTURE_SHA256[name])
                if version == 2:
                    _preamble, header, _body = decode_header_frame(encoded)
                else:
                    _frame, header = read_v3_header_frame(BytesIO(encoded))
                self.assertEqual(header.format_version, version)
                output_dir = Path(temp_dir) / f"opened-v{version}"

                result = open_hse2_archive(
                    input_path=archive,
                    output_dir=output_dir,
                    keyfile_bytes=FIXTURE_KEY,
                )

                self.assertEqual((output_dir / "fixture-payload.txt").read_bytes(), FIXTURE_PAYLOAD)


if __name__ == "__main__":
    unittest.main()
