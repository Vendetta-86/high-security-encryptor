"""Explicit two-credential compaction and v4-to-v5 export adapters."""

from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path

from ..atomic_io import atomic_output_path, flush_file
from .container_v4_credentials import unlock_v4_credentials
from .container_v4_descriptor import open_v4_descriptor
from .container_v4_file import V4ContainerReader
from .container_v4_records import open_v4_record
from .container_v4_workflows import _validate_restored_view
from .container_v5_credentials import create_v5_credentials, unlock_v5_credentials
from .container_v5_crypto import V5_MAX_CONTAINER_SIZE, V5_MAX_LIVE_CHUNKS_PER_VIEW
from .container_v5_descriptor import (
    V5ChunkReference, V5FileEntry, V5ViewDescriptor, open_v5_descriptor, seal_v5_descriptor,
)
from .container_v5_file import V5ContainerReader
from .container_v5_header import V5_FOOTER_SIZE, V5Footer, V5FooterEntry, V5PublicHeader
from .container_v5_records import open_v5_record, seal_v5_record
from .models import HSE2ModelError

PlaintextSource = Callable[[], bytes]


def _build_compact_layout(
    *, archive_id: bytes, old_views: tuple[tuple[tuple[str, int, tuple[tuple[int, int], ...]], ...],
                                             tuple[tuple[str, int, tuple[tuple[int, int], ...]], ...]],
    sources: tuple[dict[int, PlaintextSource], dict[int, PlaintextSource]],
    output_path: str | Path, passwords: tuple[str, str],
    profile_name: str, overwrite: bool,
) -> Path:
    target = Path(output_path)
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")
    credentials, new_roots = create_v5_credentials(
        passwords[0], passwords[1], archive_id=archive_id, profile_name=profile_name,
    )
    header = V5PublicHeader(archive_id, credentials)
    offset = len(header.to_bytes())
    sequences = [0, 0]
    files: list[list[V5FileEntry]] = [[], []]
    tasks: list[tuple[int, int, int, int, PlaintextSource]] = []
    for slot in range(2):
        if len(old_views[slot]) > 100_000:
            raise HSE2ModelError("v5 view has too many files")
        chunk_total = 0
        for path, size, old_chunks in sorted(old_views[slot], key=lambda item: item[0].encode("utf-8")):
            references = []
            for old_sequence, length in old_chunks:
                sequence = sequences[slot]
                reference = V5ChunkReference(sequence, offset, length)
                references.append(reference)
                tasks.append((slot, sequence, offset, length, sources[slot][old_sequence]))
                offset += 60 + length
                sequences[slot] += 1
                chunk_total += 1
            files[slot].append(V5FileEntry(path, size, tuple(references)))
        if chunk_total > V5_MAX_LIVE_CHUNKS_PER_VIEW:
            raise HSE2ModelError("v5 view exceeds live chunk limit")
    view0 = V5ViewDescriptor(0, 1, sequences[0], tuple(files[0]))
    view1 = V5ViewDescriptor(1, 1, sequences[1], tuple(files[1]))
    descriptor0 = seal_v5_descriptor(root_key=new_roots[0], archive_id=archive_id, view=view0, offset=offset)
    descriptor1_offset = offset + len(descriptor0)
    descriptor1 = seal_v5_descriptor(root_key=new_roots[1], archive_id=archive_id,
                                     view=view1, offset=descriptor1_offset)
    total_size = descriptor1_offset + len(descriptor1) + V5_FOOTER_SIZE
    if total_size > V5_MAX_CONTAINER_SIZE:
        raise HSE2ModelError("v5 container exceeds size limit")
    footer = V5Footer((
        V5FooterEntry(offset, len(descriptor0), 1),
        V5FooterEntry(descriptor1_offset, len(descriptor1), 1),
    ))
    target.parent.mkdir(parents=True, exist_ok=True)
    with atomic_output_path(target) as temp_path:
        with temp_path.open("wb") as output:
            output.write(header.to_bytes())
            for slot, sequence, record_offset, expected_length, load_plaintext in tasks:
                plaintext = load_plaintext()
                if not isinstance(plaintext, bytes) or len(plaintext) != expected_length:
                    raise HSE2ModelError("invalid plaintext chunk during v5 export")
                blob = seal_v5_record(root_key=new_roots[slot], archive_id=archive_id, slot=slot,
                                      sequence=sequence, offset=record_offset, plaintext=plaintext)
                output.write(blob)
            output.write(descriptor0)
            output.write(descriptor1)
            output.write(footer.to_bytes())
            if output.tell() != total_size:
                raise HSE2ModelError("invalid compact v5 output size")
            flush_file(output)
    return target


def compact_v5_archive(
    *, input_path: str | Path, output_path: str | Path, view_passwords: tuple[str, str],
    profile_name: str = "compatible", overwrite: bool = False,
) -> Path:
    source_path = Path(input_path)
    target = Path(output_path)
    if source_path.resolve() == target.resolve():
        raise HSE2ModelError("v5 compaction requires a new output path")
    if not isinstance(view_passwords, tuple) or len(view_passwords) != 2:
        raise HSE2ModelError("v5 compaction requires both view passwords")
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")

    old_views: list[tuple[tuple[str, int, tuple[tuple[int, int], ...]], ...]] = []
    sources: list[dict[int, PlaintextSource]] = []
    with V5ContainerReader(source_path) as reader:
        for slot, password in enumerate(view_passwords):
            unlocked_slot, root = unlock_v5_credentials(
                password, reader.header.credential_slots, archive_id=reader.header.archive_id,
            )
            if unlocked_slot != slot:
                raise HSE2ModelError("v5 compaction requires both distinct view passwords")
            generation, blob = reader.read_descriptor(slot)
            descriptor = open_v5_descriptor(
                root_key=root, archive_id=reader.header.archive_id, slot=slot,
                generation=generation, offset=reader.footer.views[slot].offset, blob=blob,
            )
            view_rows = []
            source_rows: dict[int, PlaintextSource] = {}
            for item in descriptor.files:
                chunks = []
                for chunk in item.chunks:
                    def load_chunk(ref=chunk, view_slot=slot, view_root=root):
                        record_blob = reader.read_record(offset=ref.offset, plaintext_length=ref.length)
                        return open_v5_record(
                            root_key=view_root, archive_id=reader.header.archive_id, slot=view_slot,
                            sequence=ref.sequence, offset=ref.offset,
                            plaintext_length=ref.length, blob=record_blob,
                        )
                    chunks.append((chunk.sequence, chunk.length))
                    source_rows[chunk.sequence] = load_chunk
                view_rows.append((item.path, item.size, tuple(chunks)))
            old_views.append(tuple(view_rows))
            sources.append(source_rows)
        reader.ensure_unchanged()

        new_id = os.urandom(16)
        result = _build_compact_layout(
            archive_id=new_id,
            old_views=(old_views[0], old_views[1]),
            sources=(sources[0], sources[1]),
            output_path=target, passwords=view_passwords,
            profile_name=profile_name, overwrite=overwrite,
        )
        reader.ensure_unchanged()
    return result


def export_v4_to_v5(
    *, input_path: str | Path, output_path: str | Path, view_passwords: tuple[str, str],
    profile_name: str = "compatible", overwrite: bool = False,
) -> Path:
    source_path = Path(input_path)
    target = Path(output_path)
    if source_path.resolve() == target.resolve():
        raise HSE2ModelError("v4 export requires a new output path")
    if not isinstance(view_passwords, tuple) or len(view_passwords) != 2:
        raise HSE2ModelError("v4 export requires both view passwords")
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")

    old_views: list[tuple[tuple[str, int, tuple[tuple[int, int], ...]], ...]] = []
    sources: list[dict[int, PlaintextSource]] = []
    with V4ContainerReader(source_path) as reader:
        for slot, password in enumerate(view_passwords):
            unlocked_slot, root = unlock_v4_credentials(
                password, reader.header.credential_slots, capacity_records=reader.header.capacity_records,
            )
            if unlocked_slot != slot:
                raise HSE2ModelError("v4 export requires both distinct view passwords")
            descriptor = open_v4_descriptor(
                view_root_key=root, slot=slot, capacity_records=reader.header.capacity_records,
                region=reader.read_descriptor(slot),
            )
            view_rows = []
            source_rows: dict[int, PlaintextSource] = {}
            for path, size, indices in _validate_restored_view(descriptor, slot):
                chunks = []
                for index in indices:
                    length = descriptor.record_lengths[index]
                    def load_chunk(record_index=index, chunk_length=length, view_slot=slot, view_root=root):
                        record_blob = reader.read_record(slot=view_slot, index=record_index)
                        return open_v4_record(
                            view_root_key=view_root, slot=view_slot, index=record_index,
                            record=record_blob, plaintext_length=chunk_length,
                        )
                    chunks.append((index, length))
                    source_rows[index] = load_chunk
                view_rows.append((path, size, tuple(chunks)))
            old_views.append(tuple(view_rows))
            sources.append(source_rows)

        new_id = os.urandom(16)
        return _build_compact_layout(
            archive_id=new_id,
            old_views=(old_views[0], old_views[1]),
            sources=(sources[0], sources[1]),
            output_path=target, passwords=view_passwords,
            profile_name=profile_name, overwrite=overwrite,
        )
