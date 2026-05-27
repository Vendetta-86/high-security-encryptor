"""Standalone HSE2 archive planning CLI entrypoint."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import HSE2ModelError, build_archive_assembly_plan, build_archive_entries_from_roots

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
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact single-line JSON to stdout. Report files remain pretty-printed.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        roots = tuple(Path(root) for root in args.root)
        entries = build_archive_entries_from_roots(roots)
        summary = build_archive_assembly_plan(entries, chunk_size=int(args.chunk_size))
        summary["command"] = "hse2-plan-archive"
        summary["experimental"] = True
        summary["root_count"] = len(roots)
        summary["roots"] = [str(root) for root in roots]
        summary["output_path"] = str(Path(args.output)) if args.output else None
        summary["plan_digest_sha256"] = _plan_digest_sha256(summary)
        if args.output:
            _write_json_report(Path(args.output), summary)
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-plan-archive: {exc}", file=sys.stderr)
        return 2
    print(_format_json(summary, compact=bool(args.compact)))
    return 0


def _plan_digest_sha256(payload: dict[str, Any]) -> str:
    digest_payload = {
        key: value
        for key, value in payload.items()
        if key not in {"output_path", "plan_digest_sha256"}
    }
    canonical = json.dumps(
        digest_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _format_json(payload: dict[str, Any], *, compact: bool) -> str:
    if compact:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _write_json_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_format_json(payload, compact=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
