"""Safe ZIP extraction for decrypted folder packages."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import shutil
import tempfile
import zipfile


def safe_extract_folder_archive(zip_path: str | Path, output_dir: str | Path) -> Path:
    """以安全方式解压文件夹 ZIP，阻止路径穿越。"""

    archive_path = Path(zip_path)
    destination_dir = Path(output_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zip_file:
        validated_members, root_name = _validate_zip_members(zip_file.infolist())
        final_root = destination_dir / root_name
        if final_root.exists():
            raise FileExistsError(f"extraction target already exists: {final_root}")

        staging_parent = Path(tempfile.mkdtemp(prefix=f".{root_name}.", dir=destination_dir))
        try:
            for member, normalized_member in validated_members:
                target_path = staging_parent / Path(*PurePosixPath(normalized_member).parts)
                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zip_file.open(member, "r") as source_file, target_path.open("wb") as target_file:
                    shutil.copyfileobj(source_file, target_file)
            staged_root = staging_parent / root_name
            staged_root.replace(final_root)
            return final_root
        finally:
            if staging_parent.exists():
                shutil.rmtree(staging_parent, ignore_errors=True)


def _validate_zip_member(member: zipfile.ZipInfo) -> str:
    """在解压前校验一个 ZIP 成员名称是否合法。"""

    member_name = member.filename.replace("\\", "/")
    pure_path = PurePosixPath(member_name)
    if pure_path.is_absolute():
        raise ValueError(f"zip member must be relative: {member.filename}")
    if any(part in ("", ".", "..") or ":" in part for part in pure_path.parts):
        raise ValueError(f"zip member contains unsafe path segments: {member.filename}")

    unix_mode = member.external_attr >> 16
    file_type_bits = unix_mode & 0o170000
    if file_type_bits == 0o120000:
        raise ValueError(f"zip member must not be a symlink: {member.filename}")
    return pure_path.as_posix()


def _validate_zip_members(members: list[zipfile.ZipInfo]) -> tuple[list[tuple[zipfile.ZipInfo, str]], str]:
    """Validate the complete ZIP member set before writing anything to disk."""

    if not members:
        raise ValueError("archive is empty")

    validated_members: list[tuple[zipfile.ZipInfo, str]] = []
    root_names: set[str] = set()
    seen_names: set[str] = set()
    for member in members:
        normalized_member = _validate_zip_member(member)
        if normalized_member in seen_names:
            raise ValueError(f"zip archive contains duplicate member: {normalized_member}")
        seen_names.add(normalized_member)
        root_names.add(PurePosixPath(normalized_member).parts[0])
        validated_members.append((member, normalized_member))

    if len(root_names) != 1:
        raise ValueError("archive must contain exactly one top-level folder")
    return validated_members, next(iter(root_names))
