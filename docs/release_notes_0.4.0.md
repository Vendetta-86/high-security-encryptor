# Release Notes 0.4.0

## Highlights

- Added a dedicated `移动存储加密` GUI tab for Windows removable-storage
  encryption.
- Added Windows BitLocker To Go integration for removable USB and SD volumes.
- Added removable-device discovery with drive letter, volume label, capacity,
  bus type, BitLocker status, and lock status.
- Added GUI actions for removable-drive encrypt, unlock, and lock.
- Added recovery-information export during removable-drive encryption.
- Expanded GUI guidance and validation messaging.
- Increased automated coverage to 177 tests.

## User Impact

- Encrypted removable drives now stay encrypted after unplugging.
- Reinserting a protected removable drive still requires unlocking before use.
- Unlocking restores access for the current session only; it does not remove the
  drive password.
- The removable-storage feature is Windows-only and requires administrator
  privileges for BitLocker operations.

## Verification

- `python -m unittest discover -s tests`
- `high-security-encryptor --help`
- `high-security-encryptor-gui --smoke-test`
- `python -m build`
- `dist\release-0.4.0\windows-x64\high-security-encryptor.exe --help`
- `dist\release-0.4.0\windows-x64\high-security-encryptor-gui.exe --smoke-test`
- Example config validation passed for `compatible`, `hardened`, and
  `no-password-tables` modes.

## Assets

- `high_security_encryptor-0.4.0-py3-none-any.whl`
- `high_security_encryptor-0.4.0.tar.gz`
- `high-security-encryptor-0.4.0-windows-x64.zip`

## Notes

- `compatible` example configs still report expected password-table warnings
  during validation.
- Unsigned Windows executables may still trigger SmartScreen or antivirus
  warnings on first download.
