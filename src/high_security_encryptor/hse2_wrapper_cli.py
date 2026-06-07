"""Guarded experimental HSE2 wrapper management CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import HSE2ModelError
from .hse2.access_management import list_hse2_wrappers, remove_hse2_wrapper
from .hse2.workflows import read_keyfile_bytes, read_secret_text_file

HSE2_CONTAINER_SUFFIX = ".hse2"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-wrapper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List safe HSE2 wrapper metadata without decrypting payload content.")
    list_parser.add_argument("--input", required=True, help="Input .hse2 container path.")
    list_parser.add_argument("--compact", action="store_true", help="Emit compact single-line JSON to stdout.")

    remove_parser = subparsers.add_parser("remove", help="Remove one HSE2 wrapper after authenticating the current header.")
    remove_parser.add_argument("--input", required=True, help="Input .hse2 container path.")
    remove_parser.add_argument("--output", required=True, help="Output .hse2 container path.")
    remove_parser.add_argument("--wrapper-id", required=True, help="Wrapper id to remove.")
    remove_parser.add_argument("--password-file", required=False, help="Password file used to unlock the existing container.")
    remove_parser.add_argument("--keyfile", required=False, help="Keyfile used to unlock the existing container.")
    remove_parser.add_argument("--dpapi", action="store_true", help="Allow Windows DPAPI wrappers while unlocking.")
    remove_parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing output container.")
    remove_parser.add_argument("--compact", action="store_true", help="Emit compact single-line JSON to stdout.")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "list":
            summary = _run_list(args)
        elif args.command == "remove":
            summary = _run_remove(args)
        else:  # pragma: no cover - argparse enforces command choices
            raise HSE2ModelError(f"unsupported command: {args.command}")
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-wrapper: {exc}", file=sys.stderr)
        return 2
    print(_format_json(summary, compact=bool(args.compact)))
    return 0


def _run_list(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    _validate_container_path(input_path, field_name="input")
    return list_hse2_wrappers(input_path).to_dict()


def _run_remove(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    output_path = Path(args.output)
    _validate_container_path(input_path, field_name="input")
    _validate_container_path(output_path, field_name="output")
    password = read_secret_text_file(args.password_file) if args.password_file else None
    keyfile_bytes = read_keyfile_bytes(args.keyfile) if args.keyfile else None
    return remove_hse2_wrapper(
        input_path,
        output_path,
        wrapper_id=args.wrapper_id,
        password=password,
        keyfile_bytes=keyfile_bytes,
        allow_dpapi=bool(args.dpapi),
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
