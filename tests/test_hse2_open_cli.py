import contextlib
import io
import json
import os
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_open_cli import main as open_main


class HSE2OpenCliTests(unittest.TestCase):
    def test_open_cli_restores_keyfile_only_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "a.txt").write_bytes(b"abc")
            (nested / "b.bin").write_bytes(b"0123456789")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            restored = base / "restored"

            create_stdout = io.StringIO()
            create_stderr = io.StringIO()
            with contextlib.redirect_stdout(create_stdout), contextlib.redirect_stderr(create_stderr):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--keyfile",
                    str(keyfile),
                    "--chunk-size",
                    "4",
                ])
            self.assertEqual(create_exit, 0, self._debug_payload(base, container, keyfile, restored, create_stdout, create_stderr))

            open_stdout = io.StringIO()
            open_stderr = io.StringIO()
            with contextlib.redirect_stdout(open_stdout), contextlib.redirect_stderr(open_stderr):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(keyfile),
                ])

            debug = self._debug_payload(base, container, keyfile, restored, create_stdout, create_stderr, open_stdout, open_stderr, open_exit)
            self.assertEqual(open_exit, 0, debug)
            payload = json.loads(open_stdout.getvalue())
            self.assertTrue(payload["container_opened"], debug)
            self.assertEqual(payload["wrapper_type"], "keyfile", debug)
            self.assertEqual((restored / "root" / "a.txt").read_bytes(), b"abc", debug)
            self.assertEqual((restored / "root" / "nested" / "b.bin").read_bytes(), b"0123456789", debug)

    def test_open_cli_rejects_wrong_keyfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            wrong_keyfile = base / "wrong.key"
            wrong_keyfile.write_bytes(b"w" * 32)
            container = base / "archive.hse2"
            restored = base / "restored"

            with contextlib.redirect_stdout(io.StringIO()):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--keyfile",
                    str(keyfile),
                ])
            self.assertEqual(create_exit, 0)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(wrong_keyfile),
                ])

            self.assertEqual(open_exit, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("hse2-open:", stderr.getvalue())
            self.assertFalse((restored / "root" / "a.txt").exists())

    def test_open_cli_refuses_existing_file_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "root"
            root.mkdir()
            (root / "a.txt").write_bytes(b"abc")
            keyfile = base / "archive.key"
            keyfile.write_bytes(b"k" * 32)
            container = base / "archive.hse2"
            restored = base / "restored"
            existing = restored / "root" / "a.txt"
            existing.parent.mkdir(parents=True)
            existing.write_bytes(b"existing")

            with contextlib.redirect_stdout(io.StringIO()):
                create_exit = create_main([
                    "--root",
                    str(root),
                    "--output",
                    str(container),
                    "--keyfile",
                    str(keyfile),
                ])
            self.assertEqual(create_exit, 0)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                open_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(keyfile),
                ])

            self.assertEqual(open_exit, 2)
            self.assertEqual(existing.read_bytes(), b"existing")
            self.assertIn("target already exists", stderr.getvalue())

            with contextlib.redirect_stdout(io.StringIO()):
                overwrite_exit = open_main([
                    "--input",
                    str(container),
                    "--output-dir",
                    str(restored),
                    "--keyfile",
                    str(keyfile),
                    "--overwrite",
                ])
            self.assertEqual(overwrite_exit, 0)
            self.assertEqual(existing.read_bytes(), b"abc")

    def test_open_cli_requires_unlock_material(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            container = base / "archive.hse2"
            container.write_bytes(b"not-a-container")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = open_main(["--input", str(container), "--output-dir", str(base / "out")])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("hse2-open:", stderr.getvalue())
            self.assertIn("requires --password-file, --keyfile, or both", stderr.getvalue())

    def _debug_payload(
        self,
        base: Path,
        container: Path,
        keyfile: Path,
        restored: Path,
        create_stdout: io.StringIO,
        create_stderr: io.StringIO,
        open_stdout: io.StringIO | None = None,
        open_stderr: io.StringIO | None = None,
        open_exit: int | None = None,
    ) -> str:
        data: dict[str, object] = {
            "base": str(base),
            "container_exists": container.exists(),
            "container_size": container.stat().st_size if container.exists() else None,
            "create_stdout": create_stdout.getvalue(),
            "create_stderr": create_stderr.getvalue(),
            "open_exit": open_exit,
            "open_stdout": open_stdout.getvalue() if open_stdout is not None else None,
            "open_stderr": open_stderr.getvalue() if open_stderr is not None else None,
            "restored_tree": _tree(restored),
        }
        output_path = os.environ.get("HSE2_OPEN_DEBUG_JSON")
        if output_path:
            Path(output_path).write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)


def _tree(path: Path) -> list[str]:
    if not path.exists():
        return []
    return sorted(item.relative_to(path).as_posix() for item in path.rglob("*"))


if __name__ == "__main__":
    unittest.main()
