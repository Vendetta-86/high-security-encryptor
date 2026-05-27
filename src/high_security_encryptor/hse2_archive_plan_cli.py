"""Standalone HSE2 archive planning CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .hse2 import build_archive_plan_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-plan-archive")
    parser.add_argument(
        "--root",
        action="append",
        required=True,
        help="File or directory root to include. May be supplied multiple times.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    summary = build_archive_plan_summary(tuple(Path(root) for root in args.root))
    summary["command"] = "hse2-plan-archive"
    summary["experimental"] = True
    summary["roots"] = [str(Path(root)) for root in args.root]
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
