from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from high_security_encryptor.hse2.workflows import create_hse2_archive, open_hse2_archive
from tests.interop_reference.hse2_v3_reference import read_archive, write_archive


KEYFILE = b"HSE2-independent-v3-interop-key-material"
PASSWORD = "interop-only password for HSE2 v3"  # pragma: allowlist secret
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
                self.assertEqual(hashlib.sha256(normalized[name]).digest(),
                                 hashlib.sha256(expected).digest(), name)

    def test_password_profiles_interoperate_in_both_directions(self) -> None:
        cases = (
            ("password", {"password": PASSWORD}, {"password": PASSWORD}),
            (
                "password_keyfile",
                {"password": PASSWORD, "keyfile": KEYFILE},
                {"password": PASSWORD, "keyfile_bytes": KEYFILE},
            ),
        )
        for wrapper_type, reference_factors, project_factors in cases:
            with self.subTest(wrapper_type=wrapper_type), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                reference_archive = root / f"reference-{wrapper_type}.hse2"
                reference_output = root / f"reference-opened-{wrapper_type}"
                write_archive(
                    reference_archive,
                    FILES,
                    wrapper_type=wrapper_type,
                    **reference_factors,
                )
                open_hse2_archive(
                    input_path=reference_archive,
                    output_dir=reference_output,
                    **project_factors,
                )
                opened_files = {
                    path.relative_to(reference_output).as_posix(): path.read_bytes()
                    for path in reference_output.rglob("*") if path.is_file()
                }
                self.assertEqual(opened_files, FILES)

                source = root / "source"
                source.mkdir()
                for name, content in FILES.items():
                    target = source / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
                project_archive = root / f"project-{wrapper_type}.hse2"
                create_hse2_archive(
                    roots=(source,),
                    output_path=project_archive,
                    profile_name="compatible",
                    chunk_size=64 * 1024,
                    container_format_version=3,
                    **project_factors,
                )
                independently_opened = read_archive(
                    project_archive,
                    password=PASSWORD,
                    keyfile=KEYFILE if wrapper_type == "password_keyfile" else None,
                )
                normalized = {
                    name.removeprefix("source/"): content
                    for name, content in independently_opened.items()
                }
                self.assertEqual(normalized, FILES)

    def test_password_reference_reader_rejects_wrong_password(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "reference-password.hse2"
            write_archive(archive, FILES, password=PASSWORD, wrapper_type="password")
            with self.assertRaises(ValueError):
                read_archive(archive, password="incorrect-factor")  # pragma: allowlist secret

    def test_password_keyfile_reference_reader_rejects_wrong_keyfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "reference-password-keyfile.hse2"
            write_archive(
                archive,
                FILES,
                keyfile=KEYFILE,
                password=PASSWORD,
                wrapper_type="password_keyfile",
            )
            with self.assertRaisesRegex(ValueError, "metadata does not match keyfile"):
                read_archive(
                    archive,
                    keyfile=b"different-keyfile-material-0000000",
                    password=PASSWORD,
                )


if __name__ == "__main__":
    unittest.main()
