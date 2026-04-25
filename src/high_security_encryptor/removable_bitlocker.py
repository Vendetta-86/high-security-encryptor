"""Windows removable-storage BitLocker helpers used by the GUI."""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import json
import os
from pathlib import Path
import subprocess
from typing import Any


POWERSHELL_EXECUTABLE = "powershell"


INVENTORY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$bitlockerModuleAvailable = [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
$bitlockerStatusError = $null
$bitlockerByMountPoint = @{}

if ($bitlockerModuleAvailable) {
    try {
        foreach ($bitlockerVolume in Get-BitLockerVolume) {
            if (-not $bitlockerVolume.MountPoint) {
                continue
            }
            $mountPoint = [string]$bitlockerVolume.MountPoint
            $bitlockerByMountPoint[$mountPoint.ToUpperInvariant()] = [pscustomobject]@{
                VolumeStatus = [string]$bitlockerVolume.VolumeStatus
                ProtectionStatus = [string]$bitlockerVolume.ProtectionStatus
                LockStatus = [string]$bitlockerVolume.LockStatus
                EncryptionPercentage = if ($null -ne $bitlockerVolume.EncryptionPercentage) { [int]$bitlockerVolume.EncryptionPercentage } else { $null }
                EncryptionMethod = [string]$bitlockerVolume.EncryptionMethod
                AutoUnlockEnabled = if ($null -ne $bitlockerVolume.AutoUnlockEnabled) { [bool]$bitlockerVolume.AutoUnlockEnabled } else { $null }
            }
        }
    } catch {
        $bitlockerStatusError = $_.Exception.Message
    }
}

$devices = @()
foreach ($disk in Get-Disk) {
    $busType = [string]$disk.BusType
    if ($busType -notin @('USB', 'SD')) {
        continue
    }

    foreach ($partition in Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue) {
        if (-not $partition.DriveLetter) {
            continue
        }

        $mountPoint = ('{0}:' -f [string]$partition.DriveLetter).ToUpperInvariant()
        $volume = Get-Volume -Partition $partition -ErrorAction SilentlyContinue
        if ($null -eq $volume) {
            continue
        }

        $bitlocker = $bitlockerByMountPoint[$mountPoint]
        $devices += [pscustomobject]@{
            DiskNumber = [int]$disk.Number
            MountPoint = $mountPoint
            FriendlyName = [string]$disk.FriendlyName
            BusType = $busType
            PartitionStyle = [string]$disk.PartitionStyle
            OperationalStatus = [string]($disk.OperationalStatus -join ',')
            VolumeLabel = [string]$volume.FileSystemLabel
            FileSystem = [string]$volume.FileSystem
            DriveType = [string]$volume.DriveType
            HealthStatus = [string]$volume.HealthStatus
            SizeBytes = if ($null -ne $volume.Size) { [int64]$volume.Size } else { $null }
            FreeBytes = if ($null -ne $volume.SizeRemaining) { [int64]$volume.SizeRemaining } else { $null }
            BitLockerVolumeStatus = if ($null -ne $bitlocker) { [string]$bitlocker.VolumeStatus } else { $null }
            BitLockerProtectionStatus = if ($null -ne $bitlocker) { [string]$bitlocker.ProtectionStatus } else { $null }
            BitLockerLockStatus = if ($null -ne $bitlocker) { [string]$bitlocker.LockStatus } else { $null }
            BitLockerEncryptionPercentage = if ($null -ne $bitlocker) { [int]$bitlocker.EncryptionPercentage } else { $null }
            BitLockerEncryptionMethod = if ($null -ne $bitlocker) { [string]$bitlocker.EncryptionMethod } else { $null }
            AutoUnlockEnabled = if ($null -ne $bitlocker) { [bool]$bitlocker.AutoUnlockEnabled } else { $null }
        }
    }
}

[pscustomobject]@{
    BitLockerModuleAvailable = $bitlockerModuleAvailable
    BitLockerStatusError = $bitlockerStatusError
    Devices = $devices
} | ConvertTo-Json -Depth 6 -Compress
"""


ENCRYPT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Import-Module BitLocker -ErrorAction Stop

$mountPoint = $env:HSE_MOUNT_POINT
$plainPassword = $env:HSE_BITLOCKER_PASSWORD
$recoveryDirectory = $env:HSE_RECOVERY_DIRECTORY
$encryptionMethod = $env:HSE_ENCRYPTION_METHOD
$usedSpaceOnly = $env:HSE_USED_SPACE_ONLY -eq '1'
$disableAutoUnlock = $env:HSE_DISABLE_AUTO_UNLOCK -ne '0'

if (-not (Test-Path -LiteralPath $recoveryDirectory)) {
    New-Item -ItemType Directory -Path $recoveryDirectory -Force | Out-Null
}

$existingVolume = Get-BitLockerVolume -MountPoint $mountPoint
if ($existingVolume.ProtectionStatus -eq 'On' -or $existingVolume.VolumeStatus -ne 'FullyDecrypted') {
    throw "The drive $mountPoint already has BitLocker protection or an active conversion state."
}

$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
$enableParams = @{
    MountPoint = $mountPoint
    PasswordProtector = $true
    Password = $securePassword
}
if ($encryptionMethod) {
    $enableParams['EncryptionMethod'] = $encryptionMethod
}
if ($usedSpaceOnly) {
    $enableParams['UsedSpaceOnly'] = $true
}

Enable-BitLocker @enableParams | Out-Null
Add-BitLockerKeyProtector -MountPoint $mountPoint -RecoveryPasswordProtector | Out-Null
if ($disableAutoUnlock) {
    Disable-BitLockerAutoUnlock -MountPoint $mountPoint -ErrorAction SilentlyContinue | Out-Null
}

$volume = Get-BitLockerVolume -MountPoint $mountPoint
$recoveryProtector = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
if ($null -eq $recoveryProtector) {
    throw "The drive $mountPoint does not have a recovery password protector."
}

$keyProtectorId = [string]$recoveryProtector.KeyProtectorId
$recoveryPassword = [string]$recoveryProtector.RecoveryPassword
$recoveryFile = Join-Path $recoveryDirectory ("BitLockerRecovery-{0}-{1}.txt" -f $mountPoint.TrimEnd(':'), $keyProtectorId.Trim('{}'))

@(
    "BitLocker recovery information"
    "Drive: $mountPoint"
    "Key protector ID: $keyProtectorId"
    "Recovery password: $recoveryPassword"
) | Set-Content -LiteralPath $recoveryFile -Encoding UTF8

[pscustomobject]@{
    MountPoint = $mountPoint
    VolumeStatus = [string]$volume.VolumeStatus
    ProtectionStatus = [string]$volume.ProtectionStatus
    LockStatus = [string]$volume.LockStatus
    EncryptionPercentage = if ($null -ne $volume.EncryptionPercentage) { [int]$volume.EncryptionPercentage } else { $null }
    EncryptionMethod = [string]$volume.EncryptionMethod
    AutoUnlockEnabled = if ($null -ne $volume.AutoUnlockEnabled) { [bool]$volume.AutoUnlockEnabled } else { $null }
    RecoveryFile = [string]$recoveryFile
} | ConvertTo-Json -Depth 5 -Compress
"""


UNLOCK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Import-Module BitLocker -ErrorAction Stop

$mountPoint = $env:HSE_MOUNT_POINT
$plainPassword = $env:HSE_BITLOCKER_PASSWORD
$disableAutoUnlock = $env:HSE_DISABLE_AUTO_UNLOCK -ne '0'
$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

Unlock-BitLocker -MountPoint $mountPoint -Password $securePassword | Out-Null
if ($disableAutoUnlock) {
    Disable-BitLockerAutoUnlock -MountPoint $mountPoint -ErrorAction SilentlyContinue | Out-Null
}

$volume = Get-BitLockerVolume -MountPoint $mountPoint
[pscustomobject]@{
    MountPoint = $mountPoint
    VolumeStatus = [string]$volume.VolumeStatus
    ProtectionStatus = [string]$volume.ProtectionStatus
    LockStatus = [string]$volume.LockStatus
    EncryptionPercentage = if ($null -ne $volume.EncryptionPercentage) { [int]$volume.EncryptionPercentage } else { $null }
    EncryptionMethod = [string]$volume.EncryptionMethod
    AutoUnlockEnabled = if ($null -ne $volume.AutoUnlockEnabled) { [bool]$volume.AutoUnlockEnabled } else { $null }
} | ConvertTo-Json -Depth 5 -Compress
"""


LOCK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Import-Module BitLocker -ErrorAction Stop

$mountPoint = $env:HSE_MOUNT_POINT
Lock-BitLocker -MountPoint $mountPoint -ForceDismount
$volume = Get-BitLockerVolume -MountPoint $mountPoint

[pscustomobject]@{
    MountPoint = $mountPoint
    VolumeStatus = [string]$volume.VolumeStatus
    ProtectionStatus = [string]$volume.ProtectionStatus
    LockStatus = [string]$volume.LockStatus
    EncryptionPercentage = if ($null -ne $volume.EncryptionPercentage) { [int]$volume.EncryptionPercentage } else { $null }
    EncryptionMethod = [string]$volume.EncryptionMethod
    AutoUnlockEnabled = if ($null -ne $volume.AutoUnlockEnabled) { [bool]$volume.AutoUnlockEnabled } else { $null }
} | ConvertTo-Json -Depth 5 -Compress
"""


@dataclass(frozen=True)
class RemovableStorageDevice:
    """A single removable volume exposed by Windows."""

    disk_number: int
    mount_point: str
    friendly_name: str
    bus_type: str
    partition_style: str
    operational_status: str
    volume_label: str
    file_system: str
    drive_type: str
    health_status: str
    size_bytes: int | None
    free_bytes: int | None
    bitlocker_volume_status: str | None
    bitlocker_protection_status: str | None
    bitlocker_lock_status: str | None
    bitlocker_encryption_percentage: int | None
    bitlocker_encryption_method: str | None
    auto_unlock_enabled: bool | None


@dataclass(frozen=True)
class RemovableStorageInventory:
    """Detected removable devices plus BitLocker availability details."""

    devices: tuple[RemovableStorageDevice, ...]
    is_admin: bool
    bitlocker_module_available: bool
    status_warning: str | None


@dataclass(frozen=True)
class BitLockerActionResult:
    """Structured result from a removable-storage BitLocker action."""

    mount_point: str
    volume_status: str | None
    protection_status: str | None
    lock_status: str | None
    encryption_percentage: int | None
    encryption_method: str | None
    auto_unlock_enabled: bool | None
    recovery_file: Path | None = None


class RemovableStorageError(RuntimeError):
    """Base error for Windows removable-storage operations."""


class UnsupportedPlatformError(RemovableStorageError):
    """Raised when the current platform cannot support the operation."""


class BitLockerPermissionError(RemovableStorageError):
    """Raised when BitLocker needs elevation or access is denied."""


class BitLockerOperationError(RemovableStorageError):
    """Raised when a PowerShell BitLocker command fails."""


def is_windows() -> bool:
    """Return whether the current process is running on Windows."""

    return os.name == "nt"


def is_admin() -> bool:
    """Return whether the current process is running with administrative rights."""

    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):  # pragma: no cover - platform-specific fallback.
        return False


def list_removable_storage_devices() -> RemovableStorageInventory:
    """Return removable USB/SD volumes and best-effort BitLocker status."""

    _require_windows()
    payload = _run_powershell_json(INVENTORY_SCRIPT)
    admin = is_admin()
    devices = tuple(
        _device_from_payload(raw_device)
        for raw_device in _as_list(payload.get("Devices"))
    )
    return RemovableStorageInventory(
        devices=devices,
        is_admin=admin,
        bitlocker_module_available=bool(payload.get("BitLockerModuleAvailable")),
        status_warning=_build_status_warning(
            is_admin=admin,
            bitlocker_module_available=bool(payload.get("BitLockerModuleAvailable")),
            bitlocker_status_error=_optional_string(payload.get("BitLockerStatusError")),
        ),
    )


def enable_removable_bitlocker(
    mount_point: str,
    password: str,
    *,
    recovery_directory: str | Path,
    encryption_method: str = "XtsAes256",
    used_space_only: bool = False,
    disable_auto_unlock: bool = True,
) -> BitLockerActionResult:
    """Enable BitLocker To Go on a removable volume and save recovery info."""

    _require_windows()
    _require_admin()
    if not password:
        raise ValueError("password is required")
    raw_recovery_directory = str(recovery_directory).strip()
    if not raw_recovery_directory:
        raise ValueError("recovery_directory is required")
    recovery_path = Path(raw_recovery_directory)

    payload = _run_powershell_json(
        ENCRYPT_SCRIPT,
        extra_env={
            "HSE_MOUNT_POINT": normalize_mount_point(mount_point),
            "HSE_BITLOCKER_PASSWORD": password,
            "HSE_RECOVERY_DIRECTORY": str(recovery_path),
            "HSE_ENCRYPTION_METHOD": encryption_method,
            "HSE_USED_SPACE_ONLY": "1" if used_space_only else "0",
            "HSE_DISABLE_AUTO_UNLOCK": "1" if disable_auto_unlock else "0",
        },
    )
    return _action_result_from_payload(payload)


def unlock_removable_bitlocker(
    mount_point: str,
    password: str,
    *,
    disable_auto_unlock: bool = True,
) -> BitLockerActionResult:
    """Unlock a removable BitLocker volume without removing its password."""

    _require_windows()
    _require_admin()
    if not password:
        raise ValueError("password is required")
    payload = _run_powershell_json(
        UNLOCK_SCRIPT,
        extra_env={
            "HSE_MOUNT_POINT": normalize_mount_point(mount_point),
            "HSE_BITLOCKER_PASSWORD": password,
            "HSE_DISABLE_AUTO_UNLOCK": "1" if disable_auto_unlock else "0",
        },
    )
    return _action_result_from_payload(payload)


def lock_removable_bitlocker(mount_point: str) -> BitLockerActionResult:
    """Lock a removable BitLocker volume so it becomes inaccessible."""

    _require_windows()
    _require_admin()
    payload = _run_powershell_json(
        LOCK_SCRIPT,
        extra_env={"HSE_MOUNT_POINT": normalize_mount_point(mount_point)},
    )
    return _action_result_from_payload(payload)


def open_mount_point(mount_point: str) -> None:
    """Open the selected volume in Windows Explorer."""

    _require_windows()
    os.startfile(f"{normalize_mount_point(mount_point)}\\")  # type: ignore[attr-defined]


def normalize_mount_point(value: str) -> str:
    """Normalize a user-supplied drive letter into `X:` form."""

    normalized = value.strip().upper().rstrip("\\/")
    if len(normalized) == 1 and normalized.isalpha():
        return f"{normalized}:"
    if len(normalized) == 2 and normalized[0].isalpha() and normalized[1] == ":":
        return normalized
    raise ValueError("invalid drive letter")


def _device_from_payload(raw_device: dict[str, Any]) -> RemovableStorageDevice:
    return RemovableStorageDevice(
        disk_number=int(raw_device.get("DiskNumber", 0)),
        mount_point=normalize_mount_point(str(raw_device.get("MountPoint", ""))),
        friendly_name=_optional_string(raw_device.get("FriendlyName")) or "",
        bus_type=_optional_string(raw_device.get("BusType")) or "",
        partition_style=_optional_string(raw_device.get("PartitionStyle")) or "",
        operational_status=_optional_string(raw_device.get("OperationalStatus")) or "",
        volume_label=_optional_string(raw_device.get("VolumeLabel")) or "",
        file_system=_optional_string(raw_device.get("FileSystem")) or "",
        drive_type=_optional_string(raw_device.get("DriveType")) or "",
        health_status=_optional_string(raw_device.get("HealthStatus")) or "",
        size_bytes=_optional_int(raw_device.get("SizeBytes")),
        free_bytes=_optional_int(raw_device.get("FreeBytes")),
        bitlocker_volume_status=_optional_string(raw_device.get("BitLockerVolumeStatus")),
        bitlocker_protection_status=_optional_string(raw_device.get("BitLockerProtectionStatus")),
        bitlocker_lock_status=_optional_string(raw_device.get("BitLockerLockStatus")),
        bitlocker_encryption_percentage=_optional_int(raw_device.get("BitLockerEncryptionPercentage")),
        bitlocker_encryption_method=_optional_string(raw_device.get("BitLockerEncryptionMethod")),
        auto_unlock_enabled=_optional_bool(raw_device.get("AutoUnlockEnabled")),
    )


def _action_result_from_payload(payload: dict[str, Any]) -> BitLockerActionResult:
    return BitLockerActionResult(
        mount_point=normalize_mount_point(str(payload.get("MountPoint", ""))),
        volume_status=_optional_string(payload.get("VolumeStatus")),
        protection_status=_optional_string(payload.get("ProtectionStatus")),
        lock_status=_optional_string(payload.get("LockStatus")),
        encryption_percentage=_optional_int(payload.get("EncryptionPercentage")),
        encryption_method=_optional_string(payload.get("EncryptionMethod")),
        auto_unlock_enabled=_optional_bool(payload.get("AutoUnlockEnabled")),
        recovery_file=Path(payload["RecoveryFile"]) if payload.get("RecoveryFile") else None,
    )


def _build_status_warning(
    *,
    is_admin: bool,
    bitlocker_module_available: bool,
    bitlocker_status_error: str | None,
) -> str | None:
    if not bitlocker_module_available:
        return "当前系统未检测到 BitLocker 模块，无法执行移动存储整盘加密。"
    if not is_admin:
        return "当前不是管理员权限运行，只能读取基础设备信息；BitLocker 状态、加密、解锁和上锁需要管理员权限。"
    if bitlocker_status_error:
        if _is_permission_error_message(bitlocker_status_error):
            return "当前权限不足，无法读取 BitLocker 状态。请使用管理员权限重新运行程序。"
        return f"BitLocker 状态读取失败：{bitlocker_status_error.strip()}"
    return None


def _run_powershell_json(script: str, *, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    completed = subprocess.run(
        [
            POWERSHELL_EXECUTABLE,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_build_child_environment(extra_env),
        check=False,
    )
    if completed.returncode != 0:
        _raise_for_command_error(completed.stderr or completed.stdout)
    stdout = completed.stdout.strip()
    if not stdout:
        raise BitLockerOperationError("PowerShell did not return any data.")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise BitLockerOperationError(f"PowerShell returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise BitLockerOperationError("PowerShell returned an unexpected payload.")
    return payload


def _build_child_environment(extra_env: dict[str, str] | None) -> dict[str, str]:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    return env


def _raise_for_command_error(message: str) -> None:
    normalized = message.strip()
    if not normalized:
        normalized = "BitLocker command failed."
    if _is_permission_error_message(normalized):
        raise BitLockerPermissionError("此功能需要管理员权限。请以管理员身份重新运行程序后再试。")
    if "Get-BitLockerVolume" in normalized and "not recognized" in normalized:
        raise UnsupportedPlatformError("当前系统不支持 BitLocker PowerShell 模块。")
    raise BitLockerOperationError(normalized)


def _is_permission_error_message(message: str) -> bool:
    lower_message = message.lower()
    return (
        "administrative rights" in lower_message
        or "access is denied" in lower_message
        or "permissiondenied" in lower_message
        or "拒绝访问" in message
    )


def _require_windows() -> None:
    if not is_windows():
        raise UnsupportedPlatformError("移动存储整盘加密仅支持 Windows BitLocker To Go。")


def _require_admin() -> None:
    if not is_admin():
        raise BitLockerPermissionError("此功能需要管理员权限。请以管理员身份重新运行程序后再试。")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)
