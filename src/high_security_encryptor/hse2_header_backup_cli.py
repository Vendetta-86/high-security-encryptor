"""Guarded experimental HSE2 header backup CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import HSE2ModelError
from .hse2.header_backup import export_header_backup_from_container, restore_container_header_from_backup

HSE2_CONTAINER_SUFFIX = ".hse2"
HSE2_HEADER_BACKUP_SUFFIX = ".hse2.header"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-header-backup")
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export", help="Export an authenticated HSE2 header backup from a full container.")
    export_parser.add_argument("--input", required=True, help="Source .hse2 container path.")
    export_parser.add_argument("--output", required=True, help="Target .hse2.header backup path.")
    export_parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing backup file.")
    export_parser.add_argument("--compact", action="store_true", help="Emit compact single-line JSON to stdout.")

    restore_parser = subparsers.add_parser("restore", help="Restore a container header from an HSE2 header backup.")
    restore_parser.add_argument("--input", required=True, help="Source .hse2 container whose body should be preserved.")
    restore_parser.add_argument("--backup", required=True, help="Source .hse2.header backup path.")
    restore_parser.add_argument("--output", required=True, help="Target restored .hse2 container path.")
    restore_parser.add_argument(
        "--body-offset",
        type=int,
        default=None,
        help="Manual byte offset where the encrypted container body begins. Overrides backup metadata.",
    )
    restore_parser.add_argument(
        "--no-verify-body-digest",
        action="store_true",
        help="Do not verify the encrypted body digest stored in backup metadata.",
    )
    restore_parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing restored container.")
    restore_parser.add_argument("--compact", action="store_true", help="Emit compact single-line JSON to stdout.")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "export":
            summary = _run_export(args)
        elif args.command == "restore":
            summary = _run_restore(args)
        else:  # pragma: no cover - argparse enforces command choices
            raise HSE2ModelError(f"unsupported command: {args.command}")
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-header-backup: {exc}", file=sys.stderr)
        return 2
    print(_format_json(summary, compact=bool(args.compact)))
    return 0


def _run_export(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    output_path = Path(args.output)
    _validate_container_path(input_path, field_name="input")
    _validate_header_backup_path(output_path, field_name="output")
    header, metadata = export_header_backup_from_container(
        container_path=input_path,
        backup_path=output_path,
        overwrite=bool(args.overwrite),
    )
    return {
        "command": "hse2-header-backup export",
        "experimental": True,
        "header_backup_written": True,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "wrapper_count": len(header.wrappers),
        "payload_chunk_count": header.payload_layout.chunk_count,
        "body_offset": metadata.body_offset,
        "body_size": metadata.body_size,
        "body_sha256": metadata.body_sha256,
        "container_size": metadata.container_size,
        "metadata_written": True,
    }


def _run_restore(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    backup_path = Path(args.backup)
    output_path = Path(args.output)
    _validate_container_path(input_path, field_name="input")
    _validate_header_backup_path(backup_path, field_name="backup")
    _validate_container_path(output_path, field_name="output")
    if args.body_offset is not None and args.body_offset < 0:
        raise ValueError("body-offset must be non-negative")
    header, metadata = restore_container_header_from_backup(
        container_path=input_path,
        backup_path=backup_path,
        output_path=output_path,
        overwrite=bool(args.overwrite),
        body_offset=args.body_offset,
        verify_body_digest=not bool(args.no_verify_body_digest),
    )
    summary = {
        "command": "hse2-header-backup restore",
        "experimental": True,
        "container_written": True,
        "input_path": str(input_path),
        "backup_path": str(backup_path),
        "output_path": str(output_path),
        "wrapper_count": len(header.wrappers),
        "payload_chunk_count": header.payload_layout.chunk_count,
        "body_digest_verified": bool(metadata is not None and not args.no_verify_body_digest),
        "metadata_used": metadata is not None,
    }
    if metadata is not None:
        summary.update(
            {
                "body_offset": metadata.body_offset,
                "body_size": metadata.body_size,
                "body_sha256": metadata.body_sha256,
                "container_size": metadata.container_size,
            }
        )
    if args.body_offset is not None:
        summary["manual_body_offset"] = args.body_offset
    return summary


def _validate_container_path(path: Path, *, field_name: str) -> None:
    if path.suffix.lower() != HSE2_CONTAINER_SUFFIX:
        raise ValueError(f"{field_name} path must use the .hse2 suffix")


def _validate_header_backup_path(path: Path, *, field_name: str) -> None:
    if not path.name.lower().endswith(HSE2_HEADER_BACKUP_SUFFIX):
        raise ValueError(f"{field_name} path must use the .hse2.header suffix")


def _format_json(payload: dict[str, Any], *, compact: bool) -> str:
    if compact:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
