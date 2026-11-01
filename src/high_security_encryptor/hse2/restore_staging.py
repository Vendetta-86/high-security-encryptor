"""Crash-aware leases for v5 plaintext restore staging directories."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Iterator

_LEASED_STAGE_MARKER = "v5-restore-lease1-"


class _FileLock:
    def __init__(self, path: Path, *, blocking: bool) -> None:
        self.path = path
        self.blocking = blocking
        self._file = None
        self._windows_handle = None
        self._locked = False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            self._acquire_windows_mutex()
        else:
            self._file = self.path.open("a+b")
            if self._file.seek(0, os.SEEK_END) == 0:
                self._file.write(b"\0")
                self._file.flush()
            self._file.seek(0)
            try:
                import fcntl

                mode = fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)
                fcntl.flock(self._file.fileno(), mode)
            except OSError:
                self._file.close()
                self._file = None
                raise
        self._locked = True

    def _acquire_windows_mutex(self) -> None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
        create_mutex = kernel32.CreateMutexW
        create_mutex.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
        create_mutex.restype = wintypes.HANDLE
        wait = kernel32.WaitForSingleObject
        wait.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        wait.restype = wintypes.DWORD
        handle = create_mutex(None, False, f"Local\\HSE2Restore-{self.path.stem}")
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        result = wait(handle, 0xFFFFFFFF if self.blocking else 0)
        if result in (0, 0x80):  # WAIT_OBJECT_0 or WAIT_ABANDONED
            self._windows_handle = handle
            return
        kernel32.CloseHandle(handle)
        if result == 0x102:  # WAIT_TIMEOUT
            raise BlockingIOError(11, "restore staging lock is active", str(self.path))
        raise ctypes.WinError(ctypes.get_last_error())

    def release(self) -> None:
        if self._file is None:
            if self._windows_handle is None:
                return
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
            kernel32.ReleaseMutex.argtypes = (wintypes.HANDLE,)
            kernel32.ReleaseMutex.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            try:
                if self._locked and not kernel32.ReleaseMutex(self._windows_handle):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel32.CloseHandle(self._windows_handle)
                self._windows_handle = None
                self._locked = False
            return
        try:
            if self._locked and os.name != "nt":
                self._file.seek(0)
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None
            self._locked = False


class RestoreStageLease:
    """Holds the cross-process lock protecting one staging directory."""

    def __init__(self, stage: Path, lock_path: Path) -> None:
        self.stage = stage
        self.lock_path = lock_path
        self._lock = _FileLock(lock_path, blocking=False)
        self._lock.acquire()

    def release(self) -> None:
        self._lock.release()


def _target_key(target: Path) -> str:
    stable = os.path.normcase(str(target.parent.resolve() / target.name))
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _manager_lock_path(target: Path) -> Path:
    return Path(tempfile.gettempdir()) / f"hse2-v5-restore-manager-{_target_key(target)}.lock"


def _stage_lock_path(stage: Path) -> Path:
    identity = os.path.normcase(str(stage.resolve()))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return Path(tempfile.gettempdir()) / f"hse2-v5-restore-stage-{digest}.lock"


@contextmanager
def _manager_lock(target: Path) -> Iterator[None]:
    lock = _FileLock(_manager_lock_path(target), blocking=True)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def _remove_stage_with_windows_retry(candidate: Path) -> None:
    for attempt in range(6):
        try:
            shutil.rmtree(candidate)
            return
        except PermissionError as exc:
            if getattr(exc, "winerror", None) != 32 or attempt == 5:
                raise
            time.sleep(0.02 * (2 ** attempt))


def _cleanup_stale_locked(target: Path) -> None:
    parent = target.parent
    prefix = f".{target.name}.{_LEASED_STAGE_MARKER}"
    if not parent.is_dir():
        return
    for candidate in parent.glob(f"{prefix}*"):
        if not candidate.is_dir() or candidate.is_symlink() or not candidate.name.startswith(prefix):
            continue
        lock_path = _stage_lock_path(candidate)
        lease = _FileLock(lock_path, blocking=False)
        try:
            lease.acquire()
        except OSError:
            continue
        try:
            _remove_stage_with_windows_retry(candidate)
        finally:
            lease.release()
        lock_path.unlink(missing_ok=True)


def cleanup_stale_restore_stages(target: str | Path) -> None:
    """Remove only matching staging directories whose cross-process lease is free."""

    destination = Path(target)
    if not destination.parent.is_dir():
        return
    with _manager_lock(destination):
        _cleanup_stale_locked(destination)


def create_restore_stage(target: str | Path) -> tuple[Path, RestoreStageLease]:
    """Clean abandoned stages, then create and lease a unique plaintext staging directory."""

    destination = Path(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with _manager_lock(destination):
        _cleanup_stale_locked(destination)
        stage = Path(tempfile.mkdtemp(
            prefix=f".{destination.name}.{_LEASED_STAGE_MARKER}", dir=destination.parent,
        ))
        try:
            lease = RestoreStageLease(stage, _stage_lock_path(stage))
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
    return stage, lease


def finish_restore_stage(target: str | Path, lease: RestoreStageLease, *, remove_stage: bool) -> None:
    """Release a stage lease and optionally remove its staging directory."""

    destination = Path(target)
    with _manager_lock(destination):
        try:
            if remove_stage and lease.stage.exists():
                shutil.rmtree(lease.stage)
        finally:
            lease.release()
        lease.lock_path.unlink(missing_ok=True)
