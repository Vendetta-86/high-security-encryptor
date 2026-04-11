import shutil
import subprocess
import unittest


class InstallSmokeTests(unittest.TestCase):
    def test_console_script_help_runs_after_install(self) -> None:
        """The installed console script should be importable and expose help text."""

        executable = shutil.which("high-security-encryptor")
        if executable is None:
            self.skipTest("high-security-encryptor console script is not installed")

        result = subprocess.run(
            [executable, "--help"],
            text=True,
            capture_output=True,
            check=True,
        )

        self.assertIn("high-security-encryptor", result.stdout)
        self.assertIn("encrypt-batch", result.stdout)
        self.assertIn("decrypt-batch", result.stdout)


if __name__ == "__main__":
    unittest.main()
