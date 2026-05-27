"""Standalone HSE2 archive planning CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import build_archive_assembly_plan, build_archive_entries_from_roots

DEFAULT_PLAN_CHUNK_SIZE = 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-plan-archive")
    parser.add_argument(
        "--root",
        action="append",
        required=True,
        help="File or directory root to include. May be supplied multiple times.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_PLAN_CHUNK_SIZE,
        help=f"Payload chunk size used for planning only. Defaults to {DEFAULT_PLAN_CHUNK_SIZE}.",
    )
    parser.add_argument(
        "--output",
        required=False,
        help="Optional path to write the metadata-only archive planning JSON report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    roots = tuple(Path(root) for root in args.root)
    entries = build_archive_entries_from_roots(roots)
    summary = build_archive_assembly_plan(entries, chunk_size=int(args.chunk_size))
    summary["command"] = "hse2-plan-archive"
    summary["experimental"] = True
    summary["root_count"] = len(roots)
    summary["roots"] = [str(root) for root in roots]
    if args.output:
        output_path = Path(args.output)
        summary["output_path"] = str(output_path)
        _write_json_report(output_path, summary)
    else:
        summary["output_path"] = None
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _write_json_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
