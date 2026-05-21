"""Local brute-force throttling for decryption attempts.

The guard intentionally does not modify cryptographic primitives. It records local
integrity/authentication failures for a decryption subject and blocks further
attempts for a configurable cool-down period after too many failures.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Iterable


DEFAULT_MAX_FAILURES = 5
DEFAULT_WINDOW_SECONDS = 15 * 60
DEFAULT_LOCK_SECONDS = 30 * 60
STATE_SCHEMA_VERSION = 1


class BruteForceBlockedError(RuntimeError):
    """Raised when local brute-force throttling blocks a decryption attempt."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            "too many failed decryption attempts; "
            f"try again after {retry_after_seconds} seconds"
        )


@dataclass(frozen=True)
class BruteForceGuardConfig:
    """Configuration for local decryption throttling."""

    enabled: bool = True
    max_failures: int = DEFAULT_MAX_FAILURES
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    lock_seconds: int = DEFAULT_LOCK_SECONDS
    state_path: Path | None = None

    def validate(self) -> None:
        if self.max_failures <= 0:
            raise ValueError("brute-force guard max failures must be greater than zero")
        if self.window_seconds <= 0:
            raise ValueError("brute-force guard window seconds must be greater than zero")
        if self.lock_seconds <= 0:
            raise ValueError("brute-force guard lock seconds must be greater than zero")


class BruteForceGuard:
    """Persisted local failure counter keyed by a decryption subject."""

    def __init__(self, config: BruteForceGuardConfig | None = None) -> None:
        self.config = config or BruteForceGuardConfig()
        self.config.validate()
        self.state_path = self.config.state_path or default_state_path()

    def check_allowed(self, subject: str) -> None:
        """Raise when a subject is currently locked."""

        if not self.config.enabled:
            return
        now = time.time()
        state = self._load_state()
        record = self._subject_record(state, subject)
        locked_until = float(record.get("locked_until", 0))
        if locked_until > now:
            raise BruteForceBlockedError(max(1, int(locked_until - now)))

    def record_failure(self, subject: str) -> None:
        """Record one failed authentication/integrity attempt."""

        if not self.config.enabled:
            return
        now = time.time()
        state = self._load_state()
        record = self._subject_record(state, subject)
        failures = [
            float(item)
            for item in record.get("failures", [])
            if isinstance(item, (int, float)) and now - float(item) <= self.config.window_seconds
        ]
        failures.append(now)
        record["failures"] = failures
        record["last_failure"] = now
        if len(failures) >= self.config.max_failures:
            record["locked_until"] = now + self.config.lock_seconds
            record["failures"] = []
        self._write_state(state)

    def record_success(self, subject: str) -> None:
        """Clear local failure history after a successful decryption."""

        if not self.config.enabled:
            return
        state = self._load_state()
        subjects = state.setdefault("subjects", {})
        subject_key = hash_subject(subject)
        if subject_key in subjects:
            del subjects[subject_key]
            self._write_state(state)

    def _subject_record(self, state: dict[str, Any], subject: str) -> dict[str, Any]:
        subjects = state.setdefault("subjects", {})
        subject_key = hash_subject(subject)
        record = subjects.setdefault(subject_key, {})
        if not isinstance(record, dict):
            record = {}
            subjects[subject_key] = record
        return record

    def _load_state(self) -> dict[str, Any]:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return _new_state()
        except OSError:
            return _new_state()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return _new_state()
        if not isinstance(data, dict) or data.get("version") != STATE_SCHEMA_VERSION:
            return _new_state()
        subjects = data.get("subjects")
        if not isinstance(subjects, dict):
            data["subjects"] = {}
        return data

    def _write_state(self, state: dict[str, Any]) -> None:
        """Persist guard state without making decryption depend on local state I/O."""

        temp_name: str | None = None
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True)
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{self.state_path.name}.",
                suffix=".tmp",
                dir=str(self.state_path.parent),
                text=True,
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
                    temp_file.write(payload)
                    temp_file.write("\n")
                    temp_file.flush()
                    os.fsync(temp_file.fileno())
                os.replace(temp_name, self.state_path)
                temp_name = None
            finally:
                if temp_name is not None:
                    try:
                        Path(temp_name).unlink()
                    except FileNotFoundError:
                        pass
        except OSError:
            # A local throttle must not mask the actual decryption outcome. If
            # the state location is unavailable, decryption continues without
            # persisted throttling for this attempt.
            return


def _new_state() -> dict[str, Any]:
    return {"version": STATE_SCHEMA_VERSION, "subjects": {}}


def default_state_path() -> Path:
    """Return the per-user state file used by the guard."""

    override = os.environ.get("HSE_BRUTE_FORCE_GUARD_STATE")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "HighSecurityEncryptor" / "brute_force_guard.json"
    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        return Path(xdg_state_home).expanduser() / "high-security-encryptor" / "brute_force_guard.json"
    return Path.home() / ".local" / "state" / "high-security-encryptor" / "brute_force_guard.json"


def build_decryption_subject(
    *,
    encrypted_files: Iterable[str | Path],
    manifest_path: str | Path,
    template_path: str | Path,
    password_table_path: str | Path | None,
) -> str:
    """Build a stable, non-secret subject string for a decryption plan."""

    parts = [
        "manifest=" + _normalize_path(manifest_path),
        "template=" + _normalize_path(template_path),
        "password_table=" + (_normalize_path(password_table_path) if password_table_path else "<none>"),
    ]
    parts.extend("encrypted=" + _normalize_path(path) for path in sorted(map(str, encrypted_files)))
    return "\n".join(parts)


def hash_subject(subject: str) -> str:
    """Hash subject details before writing them to disk."""

    return hashlib.sha256(subject.encode("utf-8")).hexdigest()


def _normalize_path(path: str | Path) -> str:
    return str(Path(path).expanduser().resolve(strict=False))
