"""CLI helper for authenticated v2/v3 HSE2 archive validation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .hse2 import HSE2ModelError
from .hse2.keyfile_safety import keyfile_colocation_warning
from .hse2.workflows import read_keyfile_bytes, read_secret_text_file, validate_hse2_archive


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="high-security-encryptor-hse2-archive-validate")
    parser.add_argument("--input", required=True, help="Input v2/v3 .hse2 archive path.")
    parser.add_argument("--password-file", help="UTF-8 password file used to unlock the archive.")
    parser.add_argument("--keyfile", help="Keyfile used to unlock the archive.")
    parser.add_argument("--dpapi", action="store_true", help="Allow the current Windows user DPAPI wrapper.")
    parser.add_argument("--compact", action="store_true", help="Emit compact single-line JSON.")
    return parser


def validate_archive_from_files(
    *, input_path: str, password_file: str | None, keyfile: str | None, allow_dpapi: bool
) -> dict[str, Any]:
    path = Path(input_path)
    if path.suffix.lower() != ".hse2":
        raise ValueError("input path must use the .hse2 suffix")
    warning = keyfile_colocation_warning((keyfile,), (path,))
    if warning:
        print(f"hse2-archive-validate: warning: {warning}", file=sys.stderr)
    password = read_secret_text_file(password_file) if password_file else None
    keyfile_bytes = read_keyfile_bytes(keyfile) if keyfile else None
    result = validate_hse2_archive(
        input_path=path,
        password=password,
        keyfile_bytes=keyfile_bytes,
        allow_dpapi=allow_dpapi,
    )
    return {"command": "hse2-archive-validate", **result.to_dict()}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        payload = validate_archive_from_files(
            input_path=args.input,
            password_file=args.password_file,
            keyfile=args.keyfile,
            allow_dpapi=bool(args.dpapi),
        )
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-archive-validate: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) if args.compact else json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
