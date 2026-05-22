"""Smoke tests for the standalone HSE2 GUI launcher module."""

from __future__ import annotations

import unittest

from high_security_encryptor import hse2_gui_launcher
from high_security_encryptor.hse2_gui_launcher import HSE2ExperimentalApp, _quote_argv, main


class HSE2GuiLauncherTests(unittest.TestCase):
    def test_launcher_symbols_import_without_opening_window(self) -> None:
        self.assertIsNotNone(hse2_gui_launcher)
        self.assertTrue(callable(main))
        self.assertTrue(callable(HSE2ExperimentalApp))

    def test_quote_argv_handles_spaces(self) -> None:
        self.assertEqual(
            _quote_argv(["hse2-validate", "--config", "C:/tmp/my config.json"]),
            "hse2-validate --config 'C:/tmp/my config.json'",
        )

    def test_quote_argv_handles_empty_args(self) -> None:
        self.assertEqual(_quote_argv([]), "")


if __name__ == "__main__":
    unittest.main()
