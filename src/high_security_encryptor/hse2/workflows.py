"""High-level HSE2 archive create/open workflows.

This module wires the already-isolated HSE2 primitives into a guarded archive
round trip. It stays free of prompting and GUI behavior: callers must provide
already-collected password text, keyfile bytes, and/or an explicit DPAPI mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
from typing import Any

from ..atomic_io import atomic_output_path
from .archive_assembly_plan import build_archive_assembly_plan
from .archive_manifest import build_archive_manifest
from .archive_traversal import build_archive_entries_from_roots
from .dpapi import is_dpapi_available
from .file_io import read_hse2_container, write_hse2_container
from .header_auth import attach_header_auth_tag, require_valid_header_auth_tag
from .keys import generate_dek, generate_mek
from .manifest_crypto import decrypt_manifest, encrypt_manifest
from .models import CipherSuite, HSE2Header, HSE2ModelError, ManifestPolicy, PayloadLayout
from .payload_crypto import decrypt_payload_chunk, encrypt_payload_chunk
from .container_stream import V3_MAX_CHUNK_SIZE
from .container_codec import HSE2_MAGIC, HSE2_PREAMBLE_STRUCT
from .unlock import HSE2UnlockFactors, unlock_first_matching_wrapper
from .wrapper_builders import build_dpapi_wrapper, build_keyfile_wrapper, build_password_keyfile_wrapper, build_password_wrapper
from .streaming_file_io import open_v3_container, write_v3_container


@dataclass(frozen=True)
class HSE2ArchiveCreateResult:
    """Summary returned after writing an HSE2 archive container."""

    output_path: str
    wrapper_type: str
    entry_count: int
    file_count: int
    payload_chunk_count: int
    chunk_size: int
    format_version: int = 2

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
            "format_version": self.format_version,
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
    use_dpapi: bool = False,
    profile_name: str = "hardened",
    chunk_size: int = 1024 * 1024,
    overwrite: bool = False,
    created_utc: str | None = None,
    container_format_version: int = 2,
) -> HSE2ArchiveCreateResult:
    """Create a real HSE2 archive container from selected filesystem roots."""

    if chunk_size <= 0:
        raise HSE2ModelError("chunk_size must be positive")
    if container_format_version not in (2, 3):
        raise HSE2ModelError("container_format_version must be 2 or 3")
    if container_format_version == 3 and chunk_size > V3_MAX_CHUNK_SIZE:
        raise HSE2ModelError("v3 chunk_size must not exceed 16 MiB")
    if not password and keyfile_bytes is None and not use_dpapi:
        raise HSE2ModelError("hse2-create requires --password-file, --keyfile, --dpapi, or a valid combination")
    if use_dpapi and (password or keyfile_bytes is not None):
        raise HSE2ModelError("--dpapi cannot be combined with password or keyfile wrappers in this workflow")
    if use_dpapi and not is_dpapi_available():
        raise HSE2ModelError("Windows DPAPI is only available on Windows")

    root_paths = tuple(Path(root) for root in roots)
    entries = build_archive_entries_from_roots(root_paths)
    assembly_plan = build_archive_assembly_plan(entries, chunk_size=chunk_size)
    manifest = build_archive_manifest(entries)
    manifest["payload_ranges"] = assembly_plan["payload_ranges"]
    manifest["chunk_size"] = chunk_size

    source_map = _file_source_map(root_paths)
    file_paths = tuple(source_map[str(item["path"])] for item in assembly_plan["payload_ranges"])
    expected_sizes = tuple(int(item["size"]) for item in assembly_plan["payload_ranges"])

    dek = generate_dek()
    mek = generate_mek()
    payload_chunk_count = int(assembly_plan["payload_chunk_count"])
    if container_format_version == 2:
        payload_chunks = _build_payload_chunks(file_paths, dek=dek, chunk_size=chunk_size)
    else:
        payload_chunks = _iter_payload_chunks(
            file_paths,
            expected_sizes=expected_sizes,
            dek=dek,
            chunk_size=chunk_size,
        )
    encrypted_manifest = encrypt_manifest(manifest, mek=mek)

    created = created_utc or _utc_now()
    wrapper = _build_create_wrapper(
        password=password,
        keyfile_bytes=keyfile_bytes,
        use_dpapi=use_dpapi,
        profile_name=profile_name,
        created_utc=created,
        dek=dek,
        mek=mek,
    )
    header = HSE2Header(
        created_utc=created,
        cipher_suite=CipherSuite(chunk_size=chunk_size),
        manifest_policy=ManifestPolicy(encrypted=True, store_original_paths=False, filename_policy="encrypted"),
        payload_layout=PayloadLayout(chunk_count=payload_chunk_count, payload_offset=0, footer_offset=0),
        wrappers=(wrapper.record,),
        format_version=container_format_version,
    )
    header = attach_header_auth_tag(header, mek=mek)
    if container_format_version == 2:
        write_hse2_container(
            output_path,
            header=header,
            manifest=encrypted_manifest,
            payload_chunks=payload_chunks,
            overwrite=overwrite,
        )
    else:
        write_v3_container(
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
        payload_chunk_count=payload_chunk_count,
        chunk_size=chunk_size,
        format_version=container_format_version,
    )


def open_hse2_archive(
    *,
    input_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    password: str | None = None,
    keyfile_bytes: bytes | None = None,
    allow_dpapi: bool = False,
    overwrite: bool = False,
) -> HSE2ArchiveOpenResult:
    """Open an HSE2 archive container into a destination directory."""

    if not password and keyfile_bytes is None and not allow_dpapi:
        raise HSE2ModelError("hse2-open requires --password-file, --keyfile, --dpapi, or a valid combination")
    if allow_dpapi and not is_dpapi_available():
        raise HSE2ModelError("Windows DPAPI is only available on Windows")

    factors = HSE2UnlockFactors(password=password, keyfile_bytes=keyfile_bytes, allow_dpapi=allow_dpapi)
    input_file = Path(input_path)
    version = _read_container_version(input_file)
    destination = Path(output_dir)
    if version == 2:
        container = read_hse2_container(input_file)
        unlocked = unlock_first_matching_wrapper(container.header.wrappers, factors=factors)
        require_valid_header_auth_tag(container.header, mek=unlocked.mek)
        manifest = decrypt_manifest(container.manifest, mek=unlocked.mek)
        _validate_manifest_for_open(manifest)
        _validate_payload_chunk_count(manifest, len(container.payload_chunks))
        _restore_manifest_entries(
            manifest=manifest,
            payload_chunks=container.payload_chunks,
            output_dir=destination,
            content_keys=unlocked,
            overwrite=overwrite,
        )
        chunk_count = len(container.payload_chunks)
        wrapper_type = _selected_wrapper_type(container.header.wrappers, factors)
    elif version == 3:
        unlocked_holder: list[Any] = []

        def authenticate_header(header: HSE2Header) -> None:
            unlocked = unlock_first_matching_wrapper(header.wrappers, factors=factors)
            require_valid_header_auth_tag(header, mek=unlocked.mek)
            unlocked_holder.append(unlocked)

        with open_v3_container(input_file, authenticate_header=authenticate_header) as reader:
            encrypted_manifest = reader.read_manifest()
            manifest = decrypt_manifest(encrypted_manifest, mek=unlocked_holder[0].mek)
            _validate_v3_manifest_for_open(
                manifest,
                chunk_count=reader.header.payload_layout.chunk_count,
                chunk_size=reader.header.cipher_suite.chunk_size,
            )
            targets = _preflight_restore_targets(manifest, destination, overwrite=overwrite)
            _create_restore_directories(manifest, destination)
            _restore_v3_manifest_entries(
                manifest=manifest,
                payload_chunks=reader.iter_payload_chunks(),
                targets=targets,
                content_keys=unlocked_holder[0],
                chunk_size=reader.header.cipher_suite.chunk_size,
            )
            chunk_count = reader.header.payload_layout.chunk_count
            wrapper_type = _selected_wrapper_type(reader.header.wrappers, factors)
    else:
        raise HSE2ModelError(f"unsupported HSE2 container version: {version}")

    return HSE2ArchiveOpenResult(
        input_path=str(input_file),
        output_dir=str(destination),
        wrapper_type=wrapper_type,
        entry_count=len(manifest["entries"]),
        file_count=len(manifest["payload_ranges"]),
        payload_chunk_count=chunk_count,
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


def _iter_payload_chunks(
    paths: tuple[Path, ...],
    *,
    expected_sizes: tuple[int, ...],
    dek: Any,
    chunk_size: int,
):
    """Encrypt payload blocks lazily and detect source changes after planning."""

    if len(paths) != len(expected_sizes):
        raise HSE2ModelError("payload source count does not match archive plan")
    next_index = 0
    for path, expected_size in zip(paths, expected_sizes, strict=True):
        observed_size = 0
        try:
            with path.open("rb") as handle:
                while True:
                    block = handle.read(chunk_size)
                    if not block:
                        break
                    if observed_size + len(block) > expected_size:
                        raise HSE2ModelError(
                            f"archive payload source changed after archive planning: {path}"
                        )
                    observed_size += len(block)
                    yield encrypt_payload_chunk(block, dek=dek, index=next_index)
                    next_index += 1
        except OSError as exc:
            raise HSE2ModelError(f"cannot read archive payload source: {path}") from exc
        if observed_size != expected_size:
            raise HSE2ModelError(f"archive payload source changed after archive planning: {path}")


def _build_create_wrapper(
    *,
    password: str | None,
    keyfile_bytes: bytes | None,
    use_dpapi: bool,
    profile_name: str,
    created_utc: str,
    dek: Any,
    mek: Any,
) -> Any:
    if use_dpapi:
        return build_dpapi_wrapper(
            wrapper_id="dpapi-1",
            created_utc=created_utc,
            dek=dek,
            mek=mek,
            label="windows dpapi",
        )
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


def _read_container_version(path: Path) -> int:
    try:
        with path.open("rb") as stream:
            preamble = stream.read(HSE2_PREAMBLE_STRUCT.size)
    except OSError as exc:
        raise HSE2ModelError(f"cannot read HSE2 container: {path}") from exc
    if len(preamble) != HSE2_PREAMBLE_STRUCT.size:
        raise HSE2ModelError("HSE2 preamble is truncated")
    magic, version, _encoding, _reserved, _header_length = HSE2_PREAMBLE_STRUCT.unpack(preamble)
    if magic != HSE2_MAGIC:
        raise HSE2ModelError("invalid HSE2 magic")
    if version not in (2, 3):
        raise HSE2ModelError(f"unsupported HSE2 container version: {version}")
    return version


def _validate_v3_manifest_for_open(
    manifest: dict[str, Any],
    *,
    chunk_count: int,
    chunk_size: int,
) -> None:
    _validate_manifest_for_open(manifest)
    if not manifest["entries"]:
        raise HSE2ModelError("archive manifest entries must not be empty")
    if manifest.get("chunk_size") != chunk_size:
        raise HSE2ModelError("archive manifest chunk_size does not match header")

    entries_by_path: dict[str, dict[str, Any]] = {}
    files_by_path: dict[str, dict[str, Any]] = {}
    for entry in manifest["entries"]:
        if not isinstance(entry, dict):
            raise HSE2ModelError("archive manifest entry must be a dictionary")
        path_key = _manifest_path_key(entry)
        _safe_manifest_path(path_key)
        if path_key in entries_by_path:
            raise HSE2ModelError(f"duplicate archive entry path: {path_key}")
        kind = entry.get("kind")
        size = entry.get("size")
        if not isinstance(kind, str) or kind not in {"file", "directory"}:
            raise HSE2ModelError("archive manifest entry kind is invalid")
        if type(size) is not int or size < 0:
            raise HSE2ModelError("archive file size is missing or invalid")
        if kind == "directory":
            if size != 0:
                raise HSE2ModelError("directory archive entry size must be zero")
        else:
            files_by_path[path_key] = entry
        entries_by_path[path_key] = entry

    for path_key, entry in entries_by_path.items():
        parts = PurePosixPath(path_key).parts
        for depth in range(1, len(parts)):
            ancestor = "/".join(parts[:depth])
            if entries_by_path.get(ancestor, {}).get("kind") == "file":
                raise HSE2ModelError("archive file path cannot contain another entry")

    ranges_by_path: dict[str, dict[str, Any]] = {}
    next_chunk = 0
    for payload_range in manifest["payload_ranges"]:
        if not isinstance(payload_range, dict):
            raise HSE2ModelError("payload range must be a dictionary")
        path_key = _manifest_path_key(payload_range)
        _safe_manifest_path(path_key)
        if path_key in ranges_by_path:
            raise HSE2ModelError(f"duplicate payload range for file: {path_key}")
        start = payload_range.get("start_chunk")
        count = payload_range.get("chunk_count")
        size = payload_range.get("size")
        if type(start) is not int or start != next_chunk:
            raise HSE2ModelError("payload ranges must be contiguous and ordered")
        if type(count) is not int or count < 0:
            raise HSE2ModelError("payload range chunk_count is missing or invalid")
        if type(size) is not int or size < 0:
            raise HSE2ModelError("payload range size is missing or invalid")
        expected_count = (size + chunk_size - 1) // chunk_size if size else 0
        if count != expected_count:
            raise HSE2ModelError("payload range chunk_count does not match file size")
        ranges_by_path[path_key] = payload_range
        next_chunk += count

    if set(ranges_by_path) != set(files_by_path):
        raise HSE2ModelError("payload ranges do not match archive file entries")
    for path_key, entry in files_by_path.items():
        if ranges_by_path[path_key]["size"] != entry["size"]:
            raise HSE2ModelError("payload range size does not match archive entry")
    if next_chunk != chunk_count:
        raise HSE2ModelError("payload chunk count does not match manifest ranges")


def _preflight_restore_targets(
    manifest: dict[str, Any],
    output_dir: Path,
    *,
    overwrite: bool,
) -> dict[str, Path]:
    if output_dir.exists() and not output_dir.is_dir():
        raise HSE2ModelError(f"output path is not a directory: {output_dir}")
    resolved_root = output_dir.resolve()
    targets: dict[str, Path] = {}
    for entry in manifest["entries"]:
        path_key = _manifest_path_key(entry)
        relative_path = _safe_manifest_path(path_key)
        target = output_dir.joinpath(*relative_path.parts)
        try:
            target.resolve().relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise HSE2ModelError("unsafe archive path resolves outside output directory") from exc
        targets[path_key] = target
        if entry["kind"] == "directory" and target.exists() and not target.is_dir():
            raise HSE2ModelError(f"target is not a directory: {target}")
        if entry["kind"] == "file" and target.exists() and not overwrite:
            raise HSE2ModelError(f"target already exists: {target}")
        if entry["kind"] == "file" and target.exists() and target.is_dir():
            raise HSE2ModelError(f"target is a directory: {target}")
    return targets


def _create_restore_directories(manifest: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    directories = [
        output_dir.joinpath(*_safe_manifest_path(_manifest_path_key(entry)).parts)
        for entry in manifest["entries"]
        if entry["kind"] == "directory"
    ]
    for directory in sorted(directories, key=lambda item: len(item.parts)):
        directory.mkdir(parents=True, exist_ok=True)
    for entry in manifest["entries"]:
        if entry["kind"] == "file":
            target = output_dir.joinpath(*_safe_manifest_path(_manifest_path_key(entry)).parts)
            target.parent.mkdir(parents=True, exist_ok=True)


def _restore_v3_manifest_entries(
    *,
    manifest: dict[str, Any],
    payload_chunks: Any,
    targets: dict[str, Path],
    content_keys: Any,
    chunk_size: int,
) -> None:
    ranges = {item["path"]: item for item in manifest["payload_ranges"]}
    files = sorted(
        (entry for entry in manifest["entries"] if entry["kind"] == "file"),
        key=lambda entry: ranges[entry["path"]]["start_chunk"],
    )
    chunks = iter(payload_chunks)
    for file_index, entry in enumerate(files):
        path_key = entry["path"]
        payload_range = ranges[path_key]
        written = 0
        with atomic_output_path(targets[path_key]) as temp_path:
            with temp_path.open("wb") as output:
                for _ in range(payload_range["chunk_count"]):
                    try:
                        chunk = next(chunks)
                    except StopIteration as exc:
                        raise HSE2ModelError("payload ended before manifest range was complete") from exc
                    plaintext = decrypt_payload_chunk(chunk, dek=content_keys.dek)
                    if written + len(plaintext) > entry["size"] or len(plaintext) > chunk_size:
                        raise HSE2ModelError(f"restored file size mismatch: {path_key}")
                    output.write(plaintext)
                    written += len(plaintext)
                if written != entry["size"]:
                    raise HSE2ModelError(f"restored file size mismatch: {path_key}")
                if file_index == len(files) - 1:
                    _require_payload_eof(chunks)

    if not files:
        _require_payload_eof(chunks)


def _require_payload_eof(chunks: Any) -> None:
    try:
        next(chunks)
    except StopIteration:
        return
    raise HSE2ModelError("payload chunk count exceeds validated manifest ranges")


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
        if wrapper.type == "dpapi" and factors.allow_dpapi:
            return wrapper.type
    return "unknown"


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
