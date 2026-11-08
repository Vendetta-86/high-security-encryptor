from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
GUIDE_PATH = REPO_ROOT / "docs" / "beginner" / "bitlocker-removable-practice.md"


class BeginnerBitLockerDocsTests(unittest.TestCase):
    def test_powershell_examples_are_copyable_without_console_prompts(self) -> None:
        guide = GUIDE_PATH.read_text(encoding="utf-8")
        blocks = re.findall(r"```powershell\s*\r?\n(.*?)```", guide, flags=re.DOTALL)

        self.assertGreaterEqual(len(blocks), 3)
        for index, block in enumerate(blocks, start=1):
            with self.subTest(block=index):
                self.assertNotRegex(block, r"(?m)^\s*(?:PS\s+.+?>|>>)")

    def test_bitlocker_guide_explains_status_autounlock_and_recovery_rotation(self) -> None:
        guide = GUIDE_PATH.read_text(encoding="utf-8")

        for required_text in (
            "Get-BitLockerVolume",
            "VolumeStatus",
            "ProtectionStatus",
            "LockStatus",
            "AutoUnlockEnabled",
            "Disable-BitLockerAutoUnlock",
            "Read-Host -Prompt",
            "Unlock-BitLocker -MountPoint $mountPoint -RecoveryPassword",
            "删除本地恢复文件只删除一份副本，不会撤销",
        ):
            with self.subTest(text=required_text):
                self.assertIn(required_text, guide)


if __name__ == "__main__":
    unittest.main()
