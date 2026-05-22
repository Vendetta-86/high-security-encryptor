"""Smoke tests for main-GUI-facing HSE2 entry helpers."""

from __future__ import annotations

import unittest

from high_security_encryptor import hse2_gui_entry
from high_security_encryptor.hse2_gui_entry import open_hse2_experimental_window


class HSE2GuiEntryTests(unittest.TestCase):
    def test_entry_helper_imports_without_opening_window(self) -> None:
        self.assertIsNotNone(hse2_gui_entry)
        self.assertTrue(callable(open_hse2_experimental_window))


if __name__ == "__main__":
    unittest.main()
