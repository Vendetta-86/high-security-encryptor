"""Guarded experimental HSE2 access destruction CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import HSE2ModelError
from .hse2.access_management import DESTROY_ACCESS_CONFIRMATION_PHRASE, destroy_hse2_access

HSE2_CONTAINER_SUFFIX = ".hse2"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-access")
    subparsers = parser.add_subparsers(dest="command", required=True)

    destroy_parser = subparsers.add_parser("destroy", help="Write a copy of an HSE2 container with all unlock wrappers removed.")
    destroy_parser.add_argument("--input", required=True, help="Input .hse2 container path.")
    destroy_parser.add_argument("--output", required=True, help="Output .hse2 container path.")
    destroy_parser.add_argument(
        "--confirm",
        required=True,
        help=f"Required exact confirmation phrase: {DESTROY_ACCESS_CONFIRMATION_PHRASE}",
    )
    destroy_parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing output container.")
    destroy_parser.add_argument("--compact", action="store_true", help="Emit compact single-line JSON to stdout.")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "destroy":
            summary = _run_destroy(args)
        else:  # pragma: no cover - argparse enforces command choices
            raise HSE2ModelError(f"unsupported command: {args.command}")
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-access: {exc}", file=sys.stderr)
        return 2
    print(_format_json(summary, compact=bool(args.compact)))
    return 0


def _run_destroy(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    output_path = Path(args.output)
    _validate_container_path(input_path, field_name="input")
    _validate_container_path(output_path, field_name="output")
    return destroy_hse2_access(
        input_path,
        output_path,
        confirmation_phrase=str(args.confirm),
        overwrite=bool(args.overwrite),
    ).to_dict()


def _validate_container_path(path: Path, *, field_name: str) -> None:
    if path.suffix.lower() != HSE2_CONTAINER_SUFFIX:
        raise ValueError(f"{field_name} path must use the .hse2 suffix")


def _format_json(payload: dict[str, Any], *, compact: bool) -> str:
    if compact:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
