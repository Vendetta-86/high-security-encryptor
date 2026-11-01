"""Bounded file I/O for the isolated experimental HSE2 v4 candidate."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Set
import os
from pathlib import Path
import secrets
import shutil
from typing import BinaryIO

from ..atomic_io import atomic_output_path, flush_file
from .container_v4_crypto import V4_DESCRIPTOR_SIZE, V4_RECORD_SIZE
from .container_v4_header import (
    V4_DESCRIPTOR_PAIR_SIZE,
    V4_PUBLIC_HEADER_SIZE,
    V4PublicHeader,
    validate_v4_container_size,
    v4_container_size,
)
from .container_v4_records import V4Record
from .models import HSE2ModelError

V4_DESCRIPTOR_OFFSETS = (V4_PUBLIC_HEADER_SIZE, V4_PUBLIC_HEADER_SIZE + V4_DESCRIPTOR_SIZE)
V4_RECORD_AREA_OFFSET = V4_PUBLIC_HEADER_SIZE + V4_DESCRIPTOR_PAIR_SIZE
_RANDOM_FILL_SIZE = 1024 * 1024
RecordSource = Callable[[], bytes]


def _validate_indices(
    *, capacity_records: int, view_indices: tuple[Set[int], Set[int]],
) -> set[int]:
    if not isinstance(view_indices, tuple) or len(view_indices) != 2:
        raise HSE2ModelError("v4 requires two record-index sets")
    checked: list[set[int]] = []
    for slot, indices in enumerate(view_indices):
        if not isinstance(indices, (set, frozenset)):
            raise HSE2ModelError("invalid v4 record-index set")
        normalized = set(indices)
        if any(
            type(index) is not int or not 0 <= index < capacity_records or index % 2 != slot
            for index in normalized
        ):
            raise HSE2ModelError("v4 record index is outside its view partition")
        checked.append(normalized)
    if checked[0] & checked[1]:
        raise HSE2ModelError("v4 views may not share record indices")
    return checked[0] | checked[1]


def _validate_sources(indices: set[int], sources: Mapping[int, RecordSource]) -> None:
    if not isinstance(sources, Mapping) or set(sources) != indices:
        raise HSE2ModelError("v4 record sources must match the descriptor index maps")
    if any(not callable(source) for source in sources.values()):
        raise HSE2ModelError("invalid v4 record source")


def _read_exact(file_obj: BinaryIO, size: int, error: str) -> bytes:
    data = file_obj.read(size)
    if len(data) != size:
        raise HSE2ModelError(error)
    return data


class V4ContainerReader:
    """Read fixed regions from a v4 container without loading the record area."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._file: BinaryIO | None = None
        self.header: V4PublicHeader

    def __enter__(self) -> "V4ContainerReader":
        file_obj = self.path.open("rb")
        try:
            size = os.fstat(file_obj.fileno()).st_size
            raw_header = _read_exact(file_obj, V4_PUBLIC_HEADER_SIZE, "invalid v4 container header")
            header = V4PublicHeader.from_bytes(raw_header)
            validate_v4_container_size(header, size)
        except Exception:
            file_obj.close()
            raise
        self._file = file_obj
        self.header = header
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def _require_open(self) -> BinaryIO:
        if self._file is None:
            raise HSE2ModelError("v4 container reader is not open")
        return self._file

    def read_descriptor(self, slot: int) -> bytes:
        file_obj = self._require_open()
        if type(slot) is not int or slot not in (0, 1):
            raise HSE2ModelError("invalid v4 descriptor slot")
        file_obj.seek(V4_DESCRIPTOR_OFFSETS[slot])
        return _read_exact(file_obj, V4_DESCRIPTOR_SIZE, "truncated v4 descriptor")

    def read_record(self, *, slot: int, index: int) -> bytes:
        file_obj = self._require_open()
        if type(slot) is not int or slot not in (0, 1):
            raise HSE2ModelError("invalid v4 record slot")
        if type(index) is not int or not 0 <= index < self.header.capacity_records or index % 2 != slot:
            raise HSE2ModelError("invalid v4 record index for slot")
        offset = V4_RECORD_AREA_OFFSET + index * V4_RECORD_SIZE
        file_obj.seek(offset)
        return _read_exact(file_obj, V4_RECORD_SIZE, "truncated v4 record")


def create_v4_container(
    *, output_path: str | Path, header: V4PublicHeader,
    descriptors: tuple[bytes, bytes], record_sources: Mapping[int, RecordSource],
    view_record_indices: tuple[Set[int], Set[int]], overwrite: bool = False,
) -> Path:
    """Create a fixed-capacity v4 file; free records receive fresh random bytes."""

    target = Path(output_path)
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")
    if not isinstance(descriptors, tuple) or len(descriptors) != 2 or any(
        not isinstance(region, bytes) or len(region) != V4_DESCRIPTOR_SIZE for region in descriptors
    ):
        raise HSE2ModelError("invalid v4 descriptor regions")
    owned_indices = _validate_indices(
        capacity_records=header.capacity_records, view_indices=view_record_indices
    )
    _validate_sources(owned_indices, record_sources)
    expected_size = v4_container_size(header.capacity_records)
    with atomic_output_path(target) as temp_path:
        with temp_path.open("wb") as file_obj:
            file_obj.write(header.to_bytes())
            file_obj.write(descriptors[0])
            file_obj.write(descriptors[1])
            for index in range(header.capacity_records):
                if index in owned_indices:
                    encoded = record_sources[index]()
                    V4Record.from_bytes(encoded)
                    file_obj.write(encoded)
                else:
                    file_obj.write(secrets.token_bytes(V4_RECORD_SIZE))
            if file_obj.tell() != expected_size:
                raise HSE2ModelError("invalid v4 container output size")
            flush_file(file_obj)
    return target

def update_v4_view(
    *, input_path: str | Path, output_path: str | Path, slot: int,
    new_descriptor: bytes, previous_record_indices: Set[int],
    new_record_indices: Set[int], new_record_sources: Mapping[int, RecordSource],
    overwrite: bool = False,
) -> Path:
    """Publish a copied container with one view changed; preserve input and peer view."""

    source = Path(input_path)
    target = Path(output_path)
    if source.resolve() == target.resolve():
        raise HSE2ModelError("v4 updates require a new output path")
    if target.exists() and not overwrite:
        raise HSE2ModelError("output already exists")
    if type(slot) is not int or slot not in (0, 1):
        raise HSE2ModelError("invalid v4 view slot")
    if not isinstance(new_descriptor, bytes) or len(new_descriptor) != V4_DESCRIPTOR_SIZE:
        raise HSE2ModelError("invalid v4 descriptor region")
    with V4ContainerReader(source) as reader:
        capacity = reader.header.capacity_records
        for indices in (previous_record_indices, new_record_indices):
            if not isinstance(indices, (set, frozenset)) or any(
                type(index) is not int or not 0 <= index < capacity or index % 2 != slot
                for index in indices
            ):
                raise HSE2ModelError("invalid v4 view record indices")
        if not isinstance(new_record_sources, Mapping):
            raise HSE2ModelError("invalid v4 record sources")
        if not set(new_record_indices).issubset(set(previous_record_indices) | set(new_record_sources)):
            raise HSE2ModelError("new v4 descriptor references a record without authenticated data")
        if not set(new_record_sources).issubset(set(new_record_indices)):
            raise HSE2ModelError("v4 record source is not referenced by the new descriptor")
        for source_fn in new_record_sources.values():
            if not callable(source_fn):
                raise HSE2ModelError("invalid v4 record source")
        with atomic_output_path(target) as temp_path:
            with source.open("rb") as old_file, temp_path.open("wb") as new_file:
                shutil.copyfileobj(old_file, new_file, length=_RANDOM_FILL_SIZE)
                new_file.seek(V4_DESCRIPTOR_OFFSETS[slot])
                new_file.write(new_descriptor)
                for index, source_fn in new_record_sources.items():
                    encoded = source_fn()
                    V4Record.from_bytes(encoded)
                    new_file.seek(V4_RECORD_AREA_OFFSET + index * V4_RECORD_SIZE)
                    new_file.write(encoded)
                new_file.truncate(v4_container_size(capacity))
                flush_file(new_file)
    return target

