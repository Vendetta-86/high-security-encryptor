"""Experimental file-level create and restore workflows for HSE2 v4."""

from __future__ import annotations

from collections.abc import Sequence
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
from typing import Any
import unicodedata

from .archive_manifest import validate_archive_path
from .container_v4_credentials import create_v4_credentials, unlock_v4_credentials
from .container_v4_crypto import V4_MAX_RECORDS
from .container_v4_descriptor import (
    V4ViewDescriptor,
    open_v4_descriptor,
    seal_v4_descriptor,
)
from .container_v4_file import V4ContainerReader, create_v4_container, update_v4_view
from .container_v4_header import V4PublicHeader
from .container_v4_records import V4_RECORD_PAYLOAD_SIZE, open_v4_record, seal_v4_record
from .models import HSE2ModelError

V4_MAX_MANIFEST_FILES = 100_000
V4_MAX_ARCHIVE_PATH_LENGTH = 4096
V4_MAX_FILE_BYTES = V4_MAX_RECORDS * V4_RECORD_PAYLOAD_SIZE // 2


def _checked_view_files(
    entries: Sequence[tuple[str, str | Path]],
) -> list[tuple[str, Path, os.stat_result]]:
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise HSE2ModelError("v4 view files must be a sequence")
    if len(entries) > V4_MAX_MANIFEST_FILES:
        raise HSE2ModelError("v4 manifest has too many files")
    checked: list[tuple[str, Path, os.stat_result]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise HSE2ModelError("each v4 input must contain an archive path and source path")
        archive_path, source_path = entry
        validate_archive_path(archive_path)
        if len(archive_path) > V4_MAX_ARCHIVE_PATH_LENGTH:
            raise HSE2ModelError("v4 archive path exceeds limit")
        if unicodedata.normalize("NFC", archive_path) != archive_path:
            raise HSE2ModelError("v4 archive path must use NFC Unicode")
        path_key = unicodedata.normalize("NFC", archive_path.casefold())
        if path_key in seen:
            raise HSE2ModelError("duplicate v4 archive path")
        seen.add(path_key)
        source = Path(source_path)
        if not source.is_file():
            raise HSE2ModelError("v4 input file does not exist")
        stat = source.stat()
        if stat.st_size < 0 or stat.st_size > V4_MAX_FILE_BYTES:
            raise HSE2ModelError("v4 input file exceeds capacity")
        checked.append((archive_path, source, stat))
    for path_key in seen:
        parts = PurePosixPath(path_key).parts
        if any("/".join(parts[:depth]) in seen for depth in range(1, len(parts))):
            raise HSE2ModelError("v4 file path conflicts with a parent file")
    return sorted(checked, key=lambda item: item[0])


def _plan_view(
    *, slot: int, entries: list[tuple[str, Path, os.stat_result]], capacity_records: int,
    root_key: bytes,
) -> tuple[tuple[dict[str, object], dict[int, int]], dict[int, Any], set[int]]:
    record_lengths: dict[int, int] = {}
    record_sources: dict[int, Any] = {}
    manifest_files: list[dict[str, object]] = []
    next_index = slot
    max_index = capacity_records
    for archive_path, source, initial_stat in entries:
        size = initial_stat.st_size
        chunk_count = (size + V4_RECORD_PAYLOAD_SIZE - 1) // V4_RECORD_PAYLOAD_SIZE
        records: list[int] = []
        for chunk in range(chunk_count):
            index = next_index
            next_index += 2
            if index >= max_index:
                raise HSE2ModelError("v4 view exceeds its fixed record capacity")
            offset = chunk * V4_RECORD_PAYLOAD_SIZE
            length = min(V4_RECORD_PAYLOAD_SIZE, size - offset)
            record_lengths[index] = length
            records.append(index)

            def record_source(
                path: Path = source, expected_stat: os.stat_result = initial_stat,
                chunk_offset: int = offset, chunk_length: int = length,
                record_index: int = index, view_slot: int = slot,
                view_root: bytes = root_key,
            ) -> bytes:
                with path.open("rb") as file_obj:
                    before = os.fstat(file_obj.fileno())
                    if (before.st_size, before.st_mtime_ns) != (expected_stat.st_size, expected_stat.st_mtime_ns):
                        raise HSE2ModelError("v4 input file changed during encryption")
                    file_obj.seek(chunk_offset)
                    plaintext = file_obj.read(chunk_length)
                    after = os.fstat(file_obj.fileno())
                    if len(plaintext) != chunk_length or (after.st_size, after.st_mtime_ns) != (
                        expected_stat.st_size, expected_stat.st_mtime_ns
                    ):
                        raise HSE2ModelError("v4 input file changed during encryption")
                return seal_v4_record(
                    view_root_key=view_root, slot=view_slot, index=record_index, plaintext=plaintext
                ).to_bytes()

            record_sources[index] = record_source
        manifest_files.append({"path": archive_path, "size": size, "records": records})
    manifest = {"files": manifest_files}
    return (manifest, record_lengths), record_sources, set(record_lengths)


def create_v4_archive(
    *, output_path: str | Path, view_passwords: tuple[str, str],
    view_files: tuple[Sequence[tuple[str, str | Path]], Sequence[tuple[str, str | Path]]],
    capacity_records: int, profile_name: str = "compatible", overwrite: bool = False,
) -> Path:
    """Create a v4 archive holding two independent file sets.

    Each view receives half the public record capacity. This remains an
    experimental API used by the isolated v4 CLI and GUI actions.
    """

    if not isinstance(view_passwords, tuple) or len(view_passwords) != 2:
        raise HSE2ModelError("v4 requires two view passwords")
    if not isinstance(view_files, tuple) or len(view_files) != 2:
        raise HSE2ModelError("v4 requires two view file lists")
    target = Path(output_path)
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")
    checked_views = (_checked_view_files(view_files[0]), _checked_view_files(view_files[1]))
    credentials, root_keys = create_v4_credentials(
        view_passwords[0], view_passwords[1], capacity_records=capacity_records,
        profile_name=profile_name,
    )
    planned = (
        _plan_view(slot=0, entries=checked_views[0],
                   capacity_records=capacity_records, root_key=root_keys[0]),
        _plan_view(slot=1, entries=checked_views[1],
                   capacity_records=capacity_records, root_key=root_keys[1]),
    )
    descriptors: list[bytes] = []
    for slot, (descriptor_data, _, _) in enumerate(planned):
        manifest, record_lengths = descriptor_data
        descriptor = seal_v4_descriptor(
            view_root_key=root_keys[slot], slot=slot, capacity_records=capacity_records,
            manifest=manifest, record_lengths=record_lengths,
        )
        descriptors.append(descriptor)
    all_sources = {**planned[0][1], **planned[1][1]}
    header = V4PublicHeader(capacity_records, credentials)
    return create_v4_container(
        output_path=output_path, header=header,
        descriptors=(descriptors[0], descriptors[1]), record_sources=all_sources,
        view_record_indices=(planned[0][2], planned[1][2]), overwrite=overwrite,
    )


def _validate_restored_view(descriptor: V4ViewDescriptor, slot: int) -> list[tuple[str, int, list[int]]]:
    manifest = descriptor.manifest
    files = manifest.get("files")
    if set(manifest) != {"files"} or not isinstance(files, list) or len(files) > V4_MAX_MANIFEST_FILES:
        raise HSE2ModelError("invalid v4 manifest")
    result: list[tuple[str, int, list[int]]] = []
    used_indices: set[int] = set()
    seen_paths: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "size", "records"}:
            raise HSE2ModelError("invalid v4 manifest entry")
        path = item["path"]
        size = item["size"]
        indices = item["records"]
        validate_archive_path(path)
        if len(path) > V4_MAX_ARCHIVE_PATH_LENGTH or type(size) is not int or size < 0:
            raise HSE2ModelError("invalid v4 manifest entry")
        if unicodedata.normalize("NFC", path) != path:
            raise HSE2ModelError("invalid v4 manifest path")
        path_key = unicodedata.normalize("NFC", path.casefold())
        if path_key in seen_paths:
            raise HSE2ModelError("duplicate v4 manifest path")
        seen_paths.add(path_key)
        if not isinstance(indices, list) or any(type(index) is not int for index in indices):
            raise HSE2ModelError("invalid v4 manifest record list")
        if len(set(indices)) != len(indices) or used_indices.intersection(indices):
            raise HSE2ModelError("duplicate v4 manifest record index")
        lengths: list[int] = []
        for index in indices:
            length = descriptor.record_lengths.get(index)
            if length is None:
                raise HSE2ModelError("v4 manifest references an unknown record")
            lengths.append(length)
        if sum(lengths) != size or (size == 0 and indices) or (size > 0 and not indices):
            raise HSE2ModelError("v4 manifest size does not match record lengths")
        if any(length != V4_RECORD_PAYLOAD_SIZE for length in lengths[:-1]):
            raise HSE2ModelError("invalid v4 non-final record length")
        if any(index % 2 != slot for index in indices):
            raise HSE2ModelError("invalid v4 record partition")
        used_indices.update(indices)
        result.append((path, size, indices))
    if used_indices != set(descriptor.record_lengths):
        raise HSE2ModelError("v4 descriptor has unreferenced records")
    for path_key in seen_paths:
        parts = PurePosixPath(path_key).parts
        if any("/".join(parts[:depth]) in seen_paths for depth in range(1, len(parts))):
            raise HSE2ModelError("v4 file path conflicts with a parent file")
    return result


def restore_v4_archive(
    *, input_path: str | Path, password: str, output_dir: str | Path,
) -> Path:
    """Authenticate one selected view and publish all its files as one directory."""

    target = Path(output_dir)
    if target.exists():
        raise HSE2ModelError("restore output already exists")
    stage: Path | None = None
    try:
        with V4ContainerReader(input_path) as reader:
            slot, root_key = unlock_v4_credentials(
                password, reader.header.credential_slots,
                capacity_records=reader.header.capacity_records,
            )
            descriptor = open_v4_descriptor(
                view_root_key=root_key, slot=slot,
                capacity_records=reader.header.capacity_records,
                region=reader.read_descriptor(slot),
            )
            files = _validate_restored_view(descriptor, slot)
            target.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.v4-restore-", dir=target.parent))
            for archive_path, _, indices in files:
                destination = stage.joinpath(*PurePosixPath(archive_path).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as output:
                    for index in indices:
                        length = descriptor.record_lengths[index]
                        record = reader.read_record(slot=slot, index=index)
                        plaintext = open_v4_record(
                            view_root_key=root_key, slot=slot, index=index,
                            record=record, plaintext_length=length,
                        )
                        output.write(plaintext)
            if target.exists():
                raise HSE2ModelError("restore output already exists")
            os.rename(stage, target)
            stage = None
        return target
    except (HSE2ModelError, OSError, ValueError, RecursionError) as exc:
        raise HSE2ModelError("v4 archive authentication or restore failed") from exc
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def replace_v4_view(
    *, input_path: str | Path, output_path: str | Path, password: str,
    view_files: Sequence[tuple[str, str | Path]], overwrite: bool = False,
) -> Path:
    """Replace one password-selected view while copying the peer view unchanged."""

    source_path = Path(input_path)
    target_path = Path(output_path)
    if source_path.resolve() == target_path.resolve():
        raise HSE2ModelError("v4 updates require a new output path")
    if target_path.exists() and not overwrite:
        raise HSE2ModelError("output already exists")
    checked_files = _checked_view_files(view_files)
    with V4ContainerReader(input_path) as reader:
        slot, root_key = unlock_v4_credentials(
            password, reader.header.credential_slots,
            capacity_records=reader.header.capacity_records,
        )
        old_descriptor = open_v4_descriptor(
            view_root_key=root_key, slot=slot,
            capacity_records=reader.header.capacity_records,
            region=reader.read_descriptor(slot),
        )
        _validate_restored_view(old_descriptor, slot)
        previous_indices = set(old_descriptor.record_lengths)
        planned_manifest, sources, new_indices = _plan_view(
            slot=slot, entries=checked_files,
            capacity_records=reader.header.capacity_records, root_key=root_key,
        )
        manifest, record_lengths = planned_manifest
        new_descriptor = seal_v4_descriptor(
            view_root_key=root_key, slot=slot,
            capacity_records=reader.header.capacity_records,
            manifest=manifest, record_lengths=record_lengths,
        )
    return update_v4_view(
        input_path=input_path, output_path=output_path, slot=slot,
        new_descriptor=new_descriptor, previous_record_indices=previous_indices,
        new_record_indices=new_indices, new_record_sources=sources, overwrite=overwrite,
    )
