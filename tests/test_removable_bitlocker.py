from pathlib import Path
import json
import subprocess
import unittest
from unittest.mock import patch

from high_security_encryptor import removable_bitlocker
from high_security_encryptor.removable_bitlocker import (
    BitLockerPermissionError,
    enable_removable_bitlocker,
    list_removable_storage_devices,
    normalize_mount_point,
    unlock_removable_bitlocker,
)


class RemovableBitLockerTests(unittest.TestCase):
    @patch("high_security_encryptor.removable_bitlocker.is_admin", return_value=False)
    @patch("high_security_encryptor.removable_bitlocker.subprocess.run")
    def test_list_removable_storage_devices_parses_inventory(self, run_mock, _is_admin_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "BitLockerModuleAvailable": True,
                    "BitLockerStatusError": "Access is denied.",
                    "Devices": [
                        {
                            "DiskNumber": 7,
                            "MountPoint": "E:",
                            "FriendlyName": "USB SSD",
                            "BusType": "USB",
                            "PartitionStyle": "GPT",
                            "OperationalStatus": "Online",
                            "VolumeLabel": "WORK",
                            "FileSystem": "NTFS",
                            "DriveType": "Removable",
                            "HealthStatus": "Healthy",
                            "SizeBytes": 128000000000,
                            "FreeBytes": 64000000000,
                            "BitLockerVolumeStatus": None,
                            "BitLockerProtectionStatus": None,
                            "BitLockerLockStatus": None,
                            "BitLockerEncryptionPercentage": None,
                            "BitLockerEncryptionMethod": None,
                            "AutoUnlockEnabled": None,
                        }
                    ],
                },
                ensure_ascii=False,
            ),
            stderr="",
        )

        inventory = list_removable_storage_devices()

        self.assertFalse(inventory.is_admin)
        self.assertTrue(inventory.bitlocker_module_available)
        self.assertIn("管理员权限", inventory.status_warning or "")
        self.assertEqual(len(inventory.devices), 1)
        device = inventory.devices[0]
        self.assertEqual(device.mount_point, "E:")
        self.assertEqual(device.friendly_name, "USB SSD")
        self.assertEqual(device.bus_type, "USB")
        self.assertEqual(device.size_bytes, 128000000000)

    @patch("high_security_encryptor.removable_bitlocker.is_admin", return_value=False)
    def test_enable_removable_bitlocker_requires_admin(self, _is_admin_mock) -> None:
        with self.assertRaisesRegex(BitLockerPermissionError, "管理员权限"):
            enable_removable_bitlocker("E:", "secret", recovery_directory="C:/Recovery")

    @patch("high_security_encryptor.removable_bitlocker.is_admin", return_value=True)
    def test_enable_removable_bitlocker_requires_recovery_directory(self, _is_admin_mock) -> None:
        with self.assertRaisesRegex(ValueError, "recovery_directory is required"):
            enable_removable_bitlocker("E:", "secret", recovery_directory="")

    @patch("high_security_encryptor.removable_bitlocker.is_admin", return_value=True)
    @patch("high_security_encryptor.removable_bitlocker.subprocess.run")
    def test_enable_removable_bitlocker_passes_expected_environment(self, run_mock, _is_admin_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "MountPoint": "E:",
                    "VolumeStatus": "EncryptionInProgress",
                    "ProtectionStatus": "On",
                    "LockStatus": "Unlocked",
                    "EncryptionPercentage": 4,
                    "EncryptionMethod": "Aes256",
                    "AutoUnlockEnabled": False,
                    "RecoveryFile": "C:/Recovery/BitLockerRecovery-E-guid.txt",
                },
                ensure_ascii=False,
            ),
            stderr="",
        )

        result = enable_removable_bitlocker(
            "e",
            "secret-pass",
            recovery_directory="C:/Recovery",
            encryption_method="Aes256",
            used_space_only=True,
            disable_auto_unlock=False,
        )

        self.assertEqual(result.mount_point, "E:")
        self.assertEqual(result.encryption_method, "Aes256")
        self.assertEqual(result.recovery_file, Path("C:/Recovery/BitLockerRecovery-E-guid.txt"))

        call = run_mock.call_args
        self.assertIsNotNone(call)
        self.assertIn("-NoProfile", call.args[0])
        self.assertEqual(call.kwargs["env"]["HSE_MOUNT_POINT"], "E:")
        self.assertEqual(call.kwargs["env"]["HSE_BITLOCKER_PASSWORD"], "secret-pass")
        self.assertEqual(call.kwargs["env"]["HSE_RECOVERY_DIRECTORY"], str(Path("C:/Recovery")))
        self.assertEqual(call.kwargs["env"]["HSE_ENCRYPTION_METHOD"], "Aes256")
        self.assertEqual(call.kwargs["env"]["HSE_USED_SPACE_ONLY"], "1")
        self.assertEqual(call.kwargs["env"]["HSE_DISABLE_AUTO_UNLOCK"], "0")

    @patch("high_security_encryptor.removable_bitlocker.is_admin", return_value=True)
    @patch("high_security_encryptor.removable_bitlocker.subprocess.run")
    def test_unlock_removable_bitlocker_translates_permission_errors(self, run_mock, _is_admin_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="ERROR: An attempt to access a required resource was denied.\nCheck that you have administrative rights on the computer.",
        )

        with self.assertRaisesRegex(BitLockerPermissionError, "管理员权限"):
            unlock_removable_bitlocker("E:", "secret-pass")

    def test_normalize_mount_point_accepts_drive_letter_variants(self) -> None:
        self.assertEqual(normalize_mount_point("e"), "E:")
        self.assertEqual(normalize_mount_point("e:"), "E:")
        self.assertEqual(normalize_mount_point("E:\\"), "E:")


if __name__ == "__main__":
    unittest.main()
