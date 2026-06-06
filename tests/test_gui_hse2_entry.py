import inspect
import unittest

from high_security_encryptor import gui
from high_security_encryptor.gui_hse2_entry import (
    HSE2_GUI_BUTTON_TEXT,
    HighSecurityEncryptorWithHSE2App,
    main,
)


class MainGuiHSE2EntryTests(unittest.TestCase):
    def test_hse2_gui_entry_smoke_test_reuses_main_gui_smoke_path(self) -> None:
        self.assertEqual(main(["--smoke-test"]), 0)

    def test_hse2_gui_app_extends_main_gui_with_launcher_button(self) -> None:
        self.assertTrue(issubclass(HighSecurityEncryptorWithHSE2App, gui.HighSecurityEncryptorApp))
        self.assertEqual(HSE2_GUI_BUTTON_TEXT, "打开 HSE2 实验工具")
        build_log_source = inspect.getsource(HighSecurityEncryptorWithHSE2App._build_log)
        open_handler_source = inspect.getsource(HighSecurityEncryptorWithHSE2App._open_hse2_experimental_gui)
        self.assertIn("HSE2_GUI_BUTTON_TEXT", build_log_source)
        self.assertIn("_open_hse2_experimental_gui", build_log_source)
        self.assertIn("open_hse2_experimental_window", open_handler_source)


if __name__ == "__main__":
    unittest.main()
