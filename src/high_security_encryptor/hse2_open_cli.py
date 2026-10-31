"""Guarded experimental HSE2 open CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import HSE2ModelError
from .hse2.keyfile_safety import keyfile_colocation_warning
from .hse2.workflows import open_hse2_archive, read_keyfile_bytes, read_secret_text_file, validate_hse2_archive

HSE2_CONTAINER_SUFFIX = ".hse2"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-open")
    parser.add_argument("--input", required=True, help="Input .hse2 container path.")
    parser.add_argument("--output-dir", required=True, help="Directory where archive entries will be restored.")
    parser.add_argument(
        "--password-file",
        help="UTF-8 file containing the archive password. One trailing newline is stripped.",
    )
    parser.add_argument(
        "--keyfile",
        help="Binary keyfile used to unlock keyfile or password+keyfile wrappers.",
    )
    parser.add_argument(
        "--dpapi",
        action="store_true",
        help="Allow unlocking a Windows DPAPI wrapper with the current Windows user.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing existing restored files.",
    )
    parser.add_argument(
        "--validate-before-open",
        action="store_true",
        help="Authenticate the complete archive before restoring files; avoids partial output on validation failure.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact single-line JSON to stdout.",
    )
    return parser


def main(argv: list[str] | None = None, *, password_override: str | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        input_path = Path(args.input)
        _validate_input_path(input_path)
        warning = keyfile_colocation_warning((args.keyfile,), (input_path,))
        if warning:
            print(f"hse2-open: warning: {warning}", file=sys.stderr)
        if password_override is not None and args.password_file:
            raise ValueError("password override cannot be combined with --password-file")
        password = password_override if password_override is not None else (
            read_secret_text_file(args.password_file) if args.password_file else None
        )
        keyfile_bytes = read_keyfile_bytes(args.keyfile) if args.keyfile else None
        validation = None
        if args.validate_before_open:
            validation = validate_hse2_archive(
                input_path=input_path,
                password=password,
                keyfile_bytes=keyfile_bytes,
                allow_dpapi=bool(args.dpapi),
            )
        result = open_hse2_archive(
            input_path=input_path,
            output_dir=Path(args.output_dir),
            password=password,
            keyfile_bytes=keyfile_bytes,
            allow_dpapi=bool(args.dpapi),
            overwrite=bool(args.overwrite),
        )
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-open: {exc}", file=sys.stderr)
        return 2
    summary = result.to_dict()
    if validation is not None:
        summary["pre_open_validation"] = validation.to_dict()
    print(_format_json(summary, compact=bool(args.compact)))
    return 0


def _validate_input_path(path: Path) -> None:
    if path.suffix.lower() != HSE2_CONTAINER_SUFFIX:
        raise ValueError("input path must use the .hse2 suffix")


def _format_json(payload: dict[str, Any], *, compact: bool) -> str:
    if compact:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
