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

    def test_gui_console_script_smoke_test_runs_after_install(self) -> None:
        """The installed GUI console script should expose a headless smoke path."""

        executable = shutil.which("high-security-encryptor-gui")
        if executable is None:
            self.skipTest("high-security-encryptor-gui console script is not installed")

        subprocess.run(
            [executable, "--smoke-test"],
            text=True,
            capture_output=True,
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
