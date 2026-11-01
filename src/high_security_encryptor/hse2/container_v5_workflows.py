"""Streaming create, restore, and per-view replace workflows for HSE2 v5."""

from __future__ import annotations

from collections.abc import Sequence
from itertools import groupby
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import unicodedata

from ..atomic_io import atomic_output_path, flush_file
from .archive_manifest import validate_archive_path
from .container_v5_credentials import create_v5_credentials, unlock_v5_credentials
from .container_v5_crypto import (
    V5_MAX_CHUNK_SIZE, V5_MAX_CONTAINER_SIZE, V5_MAX_LIVE_CHUNKS_PER_VIEW,
)
from .container_v5_descriptor import (
    V5ChunkReference, V5FileEntry, V5ViewDescriptor, open_v5_descriptor,
    seal_v5_descriptor,
)
from .container_v5_file import V5ContainerReader
from .container_v5_header import V5_FOOTER_SIZE, V5Footer, V5FooterEntry, V5PublicHeader
from .container_v5_records import V5_RECORD_OVERHEAD, open_v5_record, seal_v5_record
from .models import HSE2ModelError

V5_MAX_FILES_PER_VIEW = 100_000
V5_MAX_ARCHIVE_PATH_LENGTH = 4096


def _checked_view_files(entries: Sequence[tuple[str, str | Path]]) -> list[tuple[str, Path, os.stat_result]]:
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise HSE2ModelError("v5 view files must be a sequence")
    if len(entries) > V5_MAX_FILES_PER_VIEW:
        raise HSE2ModelError("v5 view has too many files")
    checked = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, tuple) or len(item) != 2:
            raise HSE2ModelError("each v5 input must contain an archive path and source path")
        archive_path, source_value = item
        validate_archive_path(archive_path)
        if "\x00" in archive_path or len(archive_path.encode("utf-8")) > V5_MAX_ARCHIVE_PATH_LENGTH:
            raise HSE2ModelError("invalid v5 archive path")
        if unicodedata.normalize("NFC", archive_path) != archive_path:
            raise HSE2ModelError("v5 archive path must use NFC Unicode")
        path_key = unicodedata.normalize("NFC", archive_path.casefold())
        if path_key in seen:
            raise HSE2ModelError("duplicate v5 archive path")
        seen.add(path_key)
        source = Path(source_value)
        if not source.is_file():
            raise HSE2ModelError("v5 input file does not exist")
        stat = source.stat()
        chunk_count = (stat.st_size + V5_MAX_CHUNK_SIZE - 1) // V5_MAX_CHUNK_SIZE
        if stat.st_size < 0 or chunk_count > V5_MAX_LIVE_CHUNKS_PER_VIEW:
            raise HSE2ModelError("v5 input file exceeds per-view capacity")
        checked.append((archive_path, source, stat))
    for path_key in seen:
        parts = PurePosixPath(path_key).parts
        if any("/".join(parts[:depth]) in seen for depth in range(1, len(parts))):
            raise HSE2ModelError("v5 file path conflicts with a parent file")
    return sorted(checked, key=lambda item: item[0].encode("utf-8"))


def _plan_view(
    *, slot: int, entries: list[tuple[str, Path, os.stat_result]], start_offset: int, first_sequence: int,
) -> tuple[V5ViewDescriptor, list[tuple[Path, os.stat_result, int, V5ChunkReference]], int, int]:
    files: list[V5FileEntry] = []
    sources: list[tuple[Path, os.stat_result, int, V5ChunkReference]] = []
    offset = start_offset
    sequence = first_sequence
    chunk_count = 0
    for archive_path, source, initial_stat in entries:
        size = initial_stat.st_size
        chunks: list[V5ChunkReference] = []
        chunk_offset = 0
        while chunk_offset < size:
            length = min(V5_MAX_CHUNK_SIZE, size - chunk_offset)
            reference = V5ChunkReference(sequence=sequence, offset=offset, length=length)
            chunks.append(reference)
            sources.append((source, initial_stat, chunk_offset, reference))
            offset += V5_RECORD_OVERHEAD + length
            sequence += 1
            chunk_offset += length
            chunk_count += 1
        files.append(V5FileEntry(path=archive_path, size=size, chunks=tuple(chunks)))
    if chunk_count > V5_MAX_LIVE_CHUNKS_PER_VIEW:
        raise HSE2ModelError("v5 view exceeds live chunk limit")
    descriptor = V5ViewDescriptor(slot, 1, sequence, tuple(files))
    return descriptor, sources, offset, sequence


def _write_planned_records(file_obj, *, sources, root_key: bytes, archive_id: bytes, slot: int) -> None:
    for source, grouped_sources in groupby(sources, key=lambda item: item[0]):
        with source.open("rb") as input_file:
            for _path, expected_stat, chunk_offset, reference in grouped_sources:
                before = os.fstat(input_file.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                    expected_stat.st_dev, expected_stat.st_ino, expected_stat.st_size,
                    expected_stat.st_mtime_ns,
                ):
                    raise HSE2ModelError("v5 input file changed during encryption")
                input_file.seek(chunk_offset)
                plaintext = input_file.read(reference.length)
                after = os.fstat(input_file.fileno())
                if len(plaintext) != reference.length or (after.st_dev, after.st_ino, after.st_size,
                                                          after.st_mtime_ns) != (
                    expected_stat.st_dev, expected_stat.st_ino, expected_stat.st_size,
                    expected_stat.st_mtime_ns,
                ):
                    raise HSE2ModelError("v5 input file changed during encryption")
                if file_obj.tell() != reference.offset:
                    raise HSE2ModelError("invalid v5 record plan offset")
                blob = seal_v5_record(
                    root_key=root_key, archive_id=archive_id, slot=slot,
                    sequence=reference.sequence, offset=reference.offset, plaintext=plaintext,
                )
                file_obj.write(blob)


def create_v5_archive(
    *, output_path: str | Path, view_passwords: tuple[str, str],
    view_files: tuple[Sequence[tuple[str, str | Path]], Sequence[tuple[str, str | Path]]],
    profile_name: str = "compatible", overwrite: bool = False,
) -> Path:
    if not isinstance(view_passwords, tuple) or len(view_passwords) != 2:
        raise HSE2ModelError("v5 requires two view passwords")
    if not isinstance(view_files, tuple) or len(view_files) != 2:
        raise HSE2ModelError("v5 requires two view file lists")
    target = Path(output_path)
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")
    checked = (_checked_view_files(view_files[0]), _checked_view_files(view_files[1]))
    if any(source.resolve() == target.resolve() for view in checked for _path, source, _stat in view):
        raise HSE2ModelError("v5 output must not overwrite an input file")
    archive_id = os.urandom(16)
    credentials, roots = create_v5_credentials(
        view_passwords[0], view_passwords[1], archive_id=archive_id, profile_name=profile_name,
    )
    header = V5PublicHeader(archive_id, credentials)
    start = len(header.to_bytes())
    view0, sources0, end0, _next0 = _plan_view(slot=0, entries=checked[0], start_offset=start, first_sequence=0)
    view1, sources1, end1, _next1 = _plan_view(slot=1, entries=checked[1], start_offset=end0, first_sequence=0)
    descriptor0 = seal_v5_descriptor(root_key=roots[0], archive_id=archive_id, view=view0, offset=end1)
    descriptor1_offset = end1 + len(descriptor0)
    descriptor1 = seal_v5_descriptor(root_key=roots[1], archive_id=archive_id, view=view1, offset=descriptor1_offset)
    total_size = descriptor1_offset + len(descriptor1) + V5_FOOTER_SIZE
    if total_size > V5_MAX_CONTAINER_SIZE:
        raise HSE2ModelError("v5 container exceeds size limit")
    footer = V5Footer((
        V5FooterEntry(end1, len(descriptor0), view0.generation),
        V5FooterEntry(descriptor1_offset, len(descriptor1), view1.generation),
    ))
    target.parent.mkdir(parents=True, exist_ok=True)
    with atomic_output_path(target) as temp_path:
        with temp_path.open("wb") as output:
            output.write(header.to_bytes())
            _write_planned_records(output, sources=sources0, root_key=roots[0], archive_id=archive_id, slot=0)
            _write_planned_records(output, sources=sources1, root_key=roots[1], archive_id=archive_id, slot=1)
            output.write(descriptor0)
            output.write(descriptor1)
            output.write(footer.to_bytes())
            if output.tell() != total_size:
                raise HSE2ModelError("invalid v5 container output size")
            flush_file(output)
    return target


def _open_selected_view(reader: V5ContainerReader, password: str) -> tuple[int, bytes, V5ViewDescriptor]:
    slot, root_key = unlock_v5_credentials(password, reader.header.credential_slots,
                                           archive_id=reader.header.archive_id)
    generation, blob = reader.read_descriptor(slot)
    descriptor = open_v5_descriptor(root_key=root_key, archive_id=reader.header.archive_id,
                                    slot=slot, generation=generation,
                                    offset=reader.footer.views[slot].offset, blob=blob)
    return slot, root_key, descriptor


def restore_v5_archive(*, input_path: str | Path, password: str, output_dir: str | Path) -> Path:
    target = Path(output_dir)
    if target.exists():
        raise HSE2ModelError("restore output already exists")
    stage: Path | None = None
    try:
        with V5ContainerReader(input_path) as reader:
            slot, root_key, descriptor = _open_selected_view(reader, password)
            target.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.v5-restore-", dir=target.parent))
            for item in descriptor.files:
                destination = stage.joinpath(*PurePosixPath(item.path).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                total_written = 0
                with destination.open("xb") as output:
                    for chunk in item.chunks:
                        blob = reader.read_record(offset=chunk.offset, plaintext_length=chunk.length)
                        plaintext = open_v5_record(
                            root_key=root_key, archive_id=reader.header.archive_id, slot=slot,
                            sequence=chunk.sequence, offset=chunk.offset,
                            plaintext_length=chunk.length, blob=blob,
                        )
                        output.write(plaintext)
                        total_written += len(plaintext)
                    if total_written != item.size:
                        raise HSE2ModelError("v5 restored file size mismatch")
                    flush_file(output)
            if target.exists():
                raise HSE2ModelError("restore output already exists")
            os.rename(stage, target)
            stage = None
        return target
    except (HSE2ModelError, OSError, ValueError, RecursionError) as exc:
        raise HSE2ModelError("v5 archive authentication or restore failed") from exc
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def replace_v5_view(
    *, input_path: str | Path, output_path: str | Path, password: str,
    view_files: Sequence[tuple[str, str | Path]], overwrite: bool = False,
) -> Path:
    source = Path(input_path)
    target = Path(output_path)
    if source.resolve() == target.resolve():
        raise HSE2ModelError("v5 updates require a new output path")
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")
    checked = _checked_view_files(view_files)
    if any(file.resolve() == target.resolve() for _path, file, _stat in checked):
        raise HSE2ModelError("v5 output must not overwrite an input file")
    with V5ContainerReader(source) as reader:
        slot, root_key, previous = _open_selected_view(reader, password)
        if previous.generation >= 0xFFFFFFFFFFFFFFFF:
            raise HSE2ModelError("v5 descriptor generation limit reached")
        base_end = reader.file_size - V5_FOOTER_SIZE
        view, sources, records_end, next_sequence = _plan_view(
            slot=slot, entries=checked, start_offset=base_end, first_sequence=previous.next_sequence,
        )
        view = V5ViewDescriptor(slot, previous.generation + 1, next_sequence, view.files)
        descriptor = seal_v5_descriptor(root_key=root_key, archive_id=reader.header.archive_id,
                                         view=view, offset=records_end)
        total_size = records_end + len(descriptor) + V5_FOOTER_SIZE
        if total_size > V5_MAX_CONTAINER_SIZE:
            raise HSE2ModelError("v5 container exceeds size limit")
        entries = list(reader.footer.views)
        entries[slot] = V5FooterEntry(records_end, len(descriptor), view.generation)
        footer = V5Footer((entries[0], entries[1]))
        target.parent.mkdir(parents=True, exist_ok=True)
        with atomic_output_path(target) as temp_path:
            with temp_path.open("wb") as new_file:
                reader.copy_prefix_to(new_file, base_end)
                reader.ensure_unchanged()
                _write_planned_records(new_file, sources=sources, root_key=root_key,
                                       archive_id=reader.header.archive_id, slot=slot)
                new_file.write(descriptor)
                new_file.write(footer.to_bytes())
                if new_file.tell() != total_size:
                    raise HSE2ModelError("invalid v5 update output size")
                flush_file(new_file)
    return target
