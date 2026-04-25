# Phase 5 Completion

Phase 5 adds a dedicated Windows removable-storage encryption workflow to the
GUI while keeping the existing file and folder encryption features unchanged.

## Scope

- Added a new `移动存储加密` GUI tab for Windows removable USB and SD volumes.
- Added removable-device discovery with drive letter, label, capacity, bus type,
  and BitLocker state display.
- Added BitLocker To Go operations for encrypt, unlock, and lock.
- Added recovery-information export during removable-drive encryption.
- Added permission-aware status reporting so non-admin runs fail clearly instead
  of crashing the GUI.
- Added tests for the new Windows removable-storage module and GUI helper
  summaries.

## Release Notes

- Version: `0.4.0`
- GUI now includes a dedicated removable-storage encryption page.
- The feature is Windows-only and relies on system BitLocker support.
- Encrypting, unlocking, and locking removable drives requires administrator
  privileges.
- Unlocking does not remove the drive password; ejecting the drive keeps it
  encrypted, and reinserting it requires unlocking again.

## Verification

- `python -m unittest discover -s tests`
- Full test suite passed with 177 tests.
