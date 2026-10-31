from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from high_security_encryptor.hse2.workflows import create_hse2_archive, open_hse2_archive
from tests.interop_reference.hse2_v3_reference import read_archive, write_archive


KEYFILE = b"HSE2-independent-v3-interop-key-material"
FILES = {
    "alpha.txt": b"independent writer -> project reader\n" * 3,
    "nested/beta.bin": bytes(range(256)) * 513,
    "empty.dat": b"",
}


class IndependentHSE2V3InteropTests(unittest.TestCase):
    def test_independent_writer_opens_with_project_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "reference.hse2"
            output = root / "opened"
            write_archive(archive, FILES, KEYFILE)
            open_hse2_archive(input_path=archive, output_dir=output, keyfile_bytes=KEYFILE)
            self.assertEqual({p.relative_to(output).as_posix(): p.read_bytes()
                              for p in output.rglob("*") if p.is_file()}, FILES)

    def test_project_writer_opens_with_independent_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            for name, content in FILES.items():
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            archive = root / "project.hse2"
            create_hse2_archive(roots=(source,), output_path=archive, keyfile_bytes=KEYFILE,
                                container_format_version=3, chunk_size=64 * 1024)
            restored = read_archive(archive, KEYFILE)
            normalized = {
                name.removeprefix("source/"): content
                for name, content in restored.items()
            }
            self.assertEqual(set(normalized), set(FILES))
            for name, expected in FILES.items():
                self.assertEqual(len(normalized[name]), len(expected), name)
                self.assertEqual(__import__("hashlib").sha256(normalized[name]).digest(),
                                 __import__("hashlib").sha256(expected).digest(), name)


if __name__ == "__main__":
    unittest.main()
