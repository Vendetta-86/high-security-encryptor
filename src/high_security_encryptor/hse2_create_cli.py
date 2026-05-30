"""Guarded experimental HSE2 create CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import HSE2ModelError, build_archive_assembly_plan, build_archive_entries_from_roots

DEFAULT_CREATE_CHUNK_SIZE = 1024 * 1024
HSE2_CONTAINER_SUFFIX = ".hse2"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-create")
    parser.add_argument(
        "--root",
        action="append",
        required=True,
        help="File or directory root to include. May be supplied multiple times.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Target .hse2 container path. Guarded skeleton does not write it unless dry-run is removed later.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CREATE_CHUNK_SIZE,
        help=f"Payload chunk size used for dry-run planning only. Defaults to {DEFAULT_CREATE_CHUNK_SIZE}.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Emit metadata-only create plan JSON without reading payload bytes or writing a container.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact single-line JSON to stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if not args.dry_run:
            raise ValueError("guarded HSE2 create currently requires --dry-run")
        output_path = Path(args.output)
        _validate_output_path(output_path)
        roots = tuple(Path(root) for root in args.root)
        entries = build_archive_entries_from_roots(roots)
        summary = build_archive_assembly_plan(entries, chunk_size=int(args.chunk_size))
        summary["command"] = "hse2-create"
        summary["experimental"] = True
        summary["dry_run"] = True
        summary["container_written"] = False
        summary["root_count"] = len(roots)
        summary["roots"] = [str(root) for root in roots]
        summary["output_path"] = str(output_path)
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-create: {exc}", file=sys.stderr)
        return 2
    print(_format_json(summary, compact=bool(args.compact)))
    return 0


def _validate_output_path(path: Path) -> None:
    if path.suffix.lower() != HSE2_CONTAINER_SUFFIX:
        raise ValueError("output path must use the .hse2 suffix")


def _format_json(payload: dict[str, Any], *, compact: bool) -> str:
    if compact:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
