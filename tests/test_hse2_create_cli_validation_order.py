import contextlib
import io
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2_create_cli import main


class HSE2CreateCliValidationOrderTests(unittest.TestCase):
    def test_create_cli_validates_output_suffix_before_root_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_root = Path(temp_dir) / "missing-root"
            output = Path(temp_dir) / "out.json"
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = main([
                    "--root",
                    str(missing_root),
                    "--output",
                    str(output),
                    "--dry-run",
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(output.exists())
            self.assertIn("hse2-create:", stderr.getvalue())
            self.assertIn("output path must use the .hse2 suffix", stderr.getvalue())
            self.assertNotIn("archive root does not exist", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
