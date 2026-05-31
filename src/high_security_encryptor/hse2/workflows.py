"""High-level HSE2 archive create/open workflows.

This module wires the already-isolated HSE2 primitives into a guarded archive
round trip. It stays free of prompting and GUI behavior: callers must provide
already-collected password text and/or keyfile bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
from typing import Any

from .archive_assembly_plan import build_archive_assembly_plan
from .archive_manifest import build_archive_manifest
from .archive_traversal import build_archive_entries_from_roots
from .file_io import read_hse2_container, write_hse2_container
from .header_auth import attach_header_auth_tag, require_valid_header_auth_tag
from .keys import generate_dek, generate_mek
from .manifest_crypto import decrypt_manifest, encrypt_manifest
from .models import CipherSuite, HSE2Header, HSE2ModelError, ManifestPolicy, PayloadLayout
from .payload_crypto import decrypt_payload_chunk, encrypt_payload_chunk
from .unlock import HSE2UnlockFactors, unlock_first_matching_wrapper
from .wrapper_builders import build_keyfile_wrapper, build_password_keyfile_wrapper, build_password_wrapper


@dataclass(frozen=True)
class HSE2ArchiveCreateResult:
    """Summary returned after writing an HSE2 archive container."""

    output_path: str
    wrapper_type: str
    entry_count: int
    file_count: int
    payload_chunk_count: int
    chunk_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-create",
            "experimental": True,
            "container_written": True,
            "output_path": self.output_path,
            "wrapper_type": self.wrapper_type,
            "entry_count": self.entry_count,
            "file_count": self.file_count,
            "payload_chunk_count": self.payload_chunk_count,
            "chunk_size": self.chunk_size,
        }


@dataclass(frozen=True)
class HSE2ArchiveOpenResult:
    """Summary returned after opening an HSE2 archive container."""

    input_path: str
    output_dir: str
    wrapper_type: str
    entry_count: int
    file_count: int
    payload_chunk_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": "hse2-open",
            "experimental": True,
            "container_opened": True,
            "input_path": self.input_path,
            "output_dir": self.output_dir,
            "wrapper_type": self.wrapper_type,
            "entry_count": self.entry_count,
            "file_count": self.file_count,
            "payload_chunk_count": self.payload_chunk_count,
        }


def create_hse2_archive(
    *,
    roots: tuple[str | os.PathLike[str], ...],
    output_path: str | os.PathLike[str],
    password: str | None = None,
    keyfile_bytes: bytes | None = None,
    profile_name: str = "hardened",
    chunk_size: int = 1024 * 1024,
    overwrite: bool = False,
    created_utc: str | None = None,
) -> HSE2ArchiveCreateResult:
    """Create a real HSE2 archive container from selected filesystem roots."""

    if chunk_size <= 0:
        raise HSE2ModelError("chunk_size must be positive")
    if not password and keyfile_bytes is None:
        raise HSE2ModelError("hse2-create requires --password-file, --keyfile, or both")

    root_paths = tuple(Path(root) for root in roots)
    entries = build_archive_entries_from_roots(root_paths)
    assembly_plan = build_archive_assembly_plan(entries, chunk_size=chunk_size)
    manifest = build_archive_manifest(entries)
    manifest["payload_ranges"] = assembly_plan["payload_ranges"]
    manifest["chunk_size"] = chunk_size

    source_map = _file_source_map(root_paths)
    file_paths = tuple(source_map[str(item["path"])] for item in assembly_plan["payload_ranges"])

    dek = generate_dek()
    mek = generate_mek()
    payload_chunks = _build_payload_chunks(file_paths, dek=dek, chunk_size=chunk_size)
    encrypted_manifest = encrypt_manifest(manifest, mek=mek)

    created = created_utc or _utc_now()
    wrapper = _build_create_wrapper(
        password=password,
        keyfile_bytes=keyfile_bytes,
        profile_name=profile_name,
        created_utc=created,
        dek=dek,
        mek=mek,
    )
    header = HSE2Header(
        created_utc=created,
        cipher_suite=CipherSuite(chunk_size=chunk_size),
        manifest_policy=ManifestPolicy(encrypted=True, store_original_paths=False, filename_policy="encrypted"),
        payload_layout=PayloadLayout(chunk_count=len(payload_chunks), payload_offset=0, footer_offset=0),
        wrappers=(wrapper.record,),
    )
    header = attach_header_auth_tag(header, mek=mek)
    write_hse2_container(
        output_path,
        header=header,
        manifest=encrypted_manifest,
        payload_chunks=payload_chunks,
        overwrite=overwrite,
    )

    return HSE2ArchiveCreateResult(
        output_path=str(Path(output_path)),
        wrapper_type=wrapper.record.type,
        entry_count=len(manifest["entries"]),
        file_count=len(assembly_plan["payload_ranges"]),
        payload_chunk_count=len(payload_chunks),
        chunk_size=chunk_size,
    )


def open_hse2_archive(
    *,
    input_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    password: str | None = None,
    keyfile_bytes: bytes | None = None,
    overwrite: bool = False,
) -> HSE2ArchiveOpenResult:
    """Open an HSE2 archive container into a destination directory."""

    if not password and keyfile_bytes is None:
        raise HSE2ModelError("hse2-open requires --password-file, --keyfile, or both")

    container = read_hse2_container(input_path)
    factors = HSE2UnlockFactors(password=password, keyfile_bytes=keyfile_bytes)
    unlocked = unlock_first_matching_wrapper(container.header.wrappers, factors=factors)
    require_valid_header_auth_tag(container.header, mek=unlocked.mek)
    manifest = decrypt_manifest(container.manifest, mek=unlocked.mek)
    _validate_manifest_for_open(manifest)
    _validate_payload_chunk_count(manifest, len(container.payload_chunks))

    destination = Path(output_dir)
    _restore_manifest_entries(
        manifest,
        payload_chunks=container.payload_chunks,
        output_dir=destination,
        content_keys=unlocked,
        overwrite=overwrite,
    )

    entries = manifest["entries"]
    payload_ranges = manifest["payload_ranges"]
    return HSE2ArchiveOpenResult(
        input_path=str(Path(input_path)),
        output_dir=str(destination),
        wrapper_type=_selected_wrapper_type(container.header.wrappers, factors),
        entry_count=len(entries),
        file_count=len(payload_ranges),
        payload_chunk_count=len(container.payload_chunks),
    )


def read_secret_text_file(path: str | os.PathLike[str]) -> str:
    """Read a password file and strip one trailing newline sequence."""

    data = Path(path).read_text(encoding="utf-8")
    return data.rstrip("\r\n")


def read_keyfile_bytes(path: str | os.PathLike[str]) -> bytes:
    """Read keyfile bytes with non-empty validation."""

    data = Path(path).read_bytes()
    if not data:
        raise HSE2ModelError("keyfile must not be empty")
    return data


def _build_payload_chunks(paths: tuple[Path, ...], *, dek: Any, chunk_size: int) -> tuple[Any, ...]:
    chunks: list[Any] = []
    next_index = 0
    for path in paths:
        try:
            with path.open("rb") as handle:
                while True:
                    block = handle.read(chunk_size)
                    if not block:
                        break
                    chunks.append(encrypt_payload_chunk(block, dek=dek, index=next_index))
                    next_index += 1
        except OSError as exc:
            raise HSE2ModelError(f"cannot read archive payload source: {path}") from exc
    return tuple(chunks)


def _build_create_wrapper(
    *,
    password: str | None,
    keyfile_bytes: bytes | None,
    profile_name: str,
    created_utc: str,
    dek: Any,
    mek: Any,
) -> Any:
    if password and keyfile_bytes is not None:
        return build_password_keyfile_wrapper(
            wrapper_id="password-keyfile-1",
            created_utc=created_utc,
            password=password,
            keyfile_bytes=keyfile_bytes,
            profile_name=profile_name,
            dek=dek,
            mek=mek,
            label="password + keyfile",
        )
    if password:
        return build_password_wrapper(
            wrapper_id="password-1",
            created_utc=created_utc,
            password=password,
            profile_name=profile_name,
            dek=dek,
            mek=mek,
            label="password",
        )
    if keyfile_bytes is not None:
        return build_keyfile_wrapper(
            wrapper_id="keyfile-1",
            created_utc=created_utc,
            keyfile_bytes=keyfile_bytes,
            dek=dek,
            mek=mek,
            label="keyfile",
        )
    raise HSE2ModelError("no wrapper material supplied")


def _file_source_map(roots: tuple[Path, ...]) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for root in roots:
        if root.is_file():
            _add_source(sources, root.name, root)
        elif root.is_dir():
            base = root.parent
            for path in sorted(root.rglob("*"), key=lambda item: _relative_posix_path(item, base)):
                if path.is_file():
                    _add_source(sources, _relative_posix_path(path, base), path)
        else:
            raise HSE2ModelError(f"archive root is not a regular file or directory: {root}")
    return sources


def _add_source(sources: dict[str, Path], archive_path: str, source: Path) -> None:
    if archive_path in sources:
        raise HSE2ModelError(f"duplicate archive path: {archive_path}")
    sources[archive_path] = source


def _relative_posix_path(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError as exc:
        raise HSE2ModelError(f"archive path is not under base: {path}") from exc


def _validate_manifest_for_open(manifest: dict[str, Any]) -> None:
    if manifest.get("format") != "HSE2-archive-manifest-v1":
        raise HSE2ModelError("unsupported HSE2 archive manifest format")
    if not isinstance(manifest.get("entries"), list):
        raise HSE2ModelError("archive manifest entries are missing or invalid")
    if not isinstance(manifest.get("payload_ranges"), list):
        raise HSE2ModelError("archive manifest payload ranges are missing or invalid")


def _validate_payload_chunk_count(manifest: dict[str, Any], actual_count: int) -> None:
    expected = 0
    for item in manifest["payload_ranges"]:
        if not isinstance(item, dict):
            raise HSE2ModelError("payload range must be a dictionary")
        _manifest_path_key(item)
        start = item.get("start_chunk")
        count = item.get("chunk_count")
        if not isinstance(start, int) or start < 0:
            raise HSE2ModelError("payload range start_chunk is missing or invalid")
        if not isinstance(count, int) or count < 0:
            raise HSE2ModelError("payload range chunk_count is missing or invalid")
        if start + count > actual_count:
            raise HSE2ModelError("payload range extends beyond available chunks")
        expected += count
    if expected != actual_count:
        raise HSE2ModelError("payload chunk count does not match manifest ranges")


def _restore_manifest_entries(
    *,
    manifest: dict[str, Any],
    payload_chunks: tuple[Any, ...],
    output_dir: Path,
    content_keys: Any,
    overwrite: bool,
) -> None:
    ranges: dict[str, dict[str, Any]] = {}
    for item in manifest["payload_ranges"]:
        if not isinstance(item, dict):
            raise HSE2ModelError("payload range must be a dictionary")
        path_key = _manifest_path_key(item)
        if path_key in ranges:
            raise HSE2ModelError(f"duplicate payload range for file: {path_key}")
        ranges[path_key] = item

    for item in manifest["entries"]:
        if not isinstance(item, dict):
            raise HSE2ModelError("archive manifest entry must be a dictionary")
        archive_path = _manifest_path_key(item)
        relative_path = _safe_manifest_path(archive_path)
        target = output_dir.joinpath(*relative_path.parts)
        kind = item.get("kind")
        if kind == "directory":
            target.mkdir(parents=True, exist_ok=True)
            continue
        if kind != "file":
            raise HSE2ModelError("archive manifest entry kind is invalid")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            raise HSE2ModelError(f"target already exists: {target}")
        payload_range = ranges.get(archive_path)
        if payload_range is None:
            raise HSE2ModelError(f"payload range missing for file: {archive_path}")
        plaintext = _decrypt_file_range(payload_range, payload_chunks=payload_chunks, dek=content_keys.dek)
        expected_size = item.get("size")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise HSE2ModelError("archive file size is missing or invalid")
        if len(plaintext) != expected_size:
            raise HSE2ModelError(f"restored file size mismatch: {archive_path}")
        _atomic_write_file(target, plaintext)


def _decrypt_file_range(payload_range: dict[str, Any], *, payload_chunks: tuple[Any, ...], dek: Any) -> bytes:
    start = payload_range.get("start_chunk")
    count = payload_range.get("chunk_count")
    if not isinstance(start, int) or start < 0:
        raise HSE2ModelError("payload range start_chunk is missing or invalid")
    if not isinstance(count, int) or count < 0:
        raise HSE2ModelError("payload range chunk_count is missing or invalid")
    if count == 0:
        return b""
    end = start + count
    selected = payload_chunks[start:end]
    if len(selected) != count:
        raise HSE2ModelError("payload range extends beyond available chunks")
    return b"".join(decrypt_payload_chunk(chunk, dek=dek) for chunk in selected)


def _manifest_path_key(item: dict[str, Any]) -> str:
    value = item.get("path")
    if not isinstance(value, str):
        raise HSE2ModelError("archive manifest path is missing or invalid")
    return value


def _safe_manifest_path(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        raise HSE2ModelError("unsafe archive path in manifest")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HSE2ModelError("unsafe archive path in manifest")
    return path


def _atomic_write_file(target: Path, data: bytes) -> None:
    import tempfile

    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        finally:
            raise


def _selected_wrapper_type(wrappers: tuple[Any, ...], factors: HSE2UnlockFactors) -> str:
    # Re-run only the lightweight compatibility selection path for the summary. Any
    # authentication error would have already been raised by the real unlock above.
    for wrapper in wrappers:
        if wrapper.type == "password" and factors.password is not None:
            return wrapper.type
        if wrapper.type == "keyfile" and factors.keyfile_bytes is not None:
            return wrapper.type
        if wrapper.type == "password_keyfile" and factors.password is not None and factors.keyfile_bytes is not None:
            return wrapper.type
    return "unknown"


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
