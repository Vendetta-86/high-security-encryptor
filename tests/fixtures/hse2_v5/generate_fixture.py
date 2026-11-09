"""Regenerate the frozen HSE2 v5 archive fixture (test use only)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets

from high_security_encryptor.hse2.container_v5_workflows import create_v5_archive


FIXTURE_DIR = Path(__file__).resolve().parent
PRIMARY_FIXTURE_CREDENTIAL = "hse2-v5-fixture-primary-only"
SECONDARY_FIXTURE_CREDENTIAL = "hse2-v5-fixture-secondary-only"


class _FixtureBytes:
    """Deterministic test-only bytes; never used by product code."""

    def __init__(self) -> None:
        self._counter = 0

    def __call__(self, length: int) -> bytes:
        output = bytearray()
        while len(output) < length:
            block = hashlib.sha256(
                b"HSE2 v5 frozen fixture only\0" + self._counter.to_bytes(8, "big")
            ).digest()
            self._counter += 1
            output.extend(block)
        return bytes(output[:length])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    payload_root = FIXTURE_DIR / "expected"
    primary_root = payload_root / "primary"
    secondary_root = payload_root / "secondary"
    primary_root.mkdir(parents=True, exist_ok=True)
    secondary_root.mkdir(parents=True, exist_ok=True)

    primary_note = primary_root / "notes.txt"
    empty_file = primary_root / "empty.txt"
    secondary_note = secondary_root / "backup.bin"
    primary_note.write_bytes(b"Frozen v5 fixture: primary view.\n")
    empty_file.write_bytes(b"")
    secondary_note.write_bytes(bytes(range(128)))

    fixture_bytes = _FixtureBytes()
    archive = FIXTURE_DIR / "complete_archive.hse2"
    # This script runs as an isolated test utility. The production code keeps
    # its normal OS CSPRNG calls and exposes no deterministic-randomness option.
    original_token_bytes = secrets.token_bytes
    original_urandom = os.urandom
    try:
        secrets.token_bytes = fixture_bytes
        os.urandom = fixture_bytes
        create_v5_archive(
            output_path=archive,
            view_passwords=(PRIMARY_FIXTURE_CREDENTIAL, SECONDARY_FIXTURE_CREDENTIAL),
            view_files=(
                (("empty.txt", empty_file), ("notes.txt", primary_note)),
                (("backup.bin", secondary_note),),
            ),
            overwrite=True,
        )
    finally:
        secrets.token_bytes = original_token_bytes
        os.urandom = original_urandom

    manifest = {
        "archive": {
            "file": archive.name,
            "size_bytes": archive.stat().st_size,
        },
        "fixture_only": True,
        "schema": 1,
        "views": [
            {
                "files": [
                    {"path": "empty.txt", "size_bytes": 0},
                    {"path": "notes.txt", "size_bytes": primary_note.stat().st_size},
                ],
                "slot": 0,
            },
            {
                "files": [
                    {"path": "backup.bin", "size_bytes": secondary_note.stat().st_size},
                ],
                "slot": 1,
            },
        ],
    }
    (FIXTURE_DIR / "complete_archive.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    checksums = (
        (archive, "complete_archive.hse2"),
        (empty_file, "expected/primary/empty.txt"),
        (primary_note, "expected/primary/notes.txt"),
        (secondary_note, "expected/secondary/backup.bin"),
    )
    (FIXTURE_DIR / "complete_archive.sha256").write_text(
        "".join(f"{_sha256(path)}  {label}  # pragma: allowlist secret\n"
                for path, label in checksums),
        encoding="ascii",
    )


if __name__ == "__main__":
    main()
