"""Guarded experimental HSE2 wrapper management CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .dpapi_guidance import DPAPI_WRAPPER_PORTABILITY_WARNING
from .hse2 import HSE2ModelError
from .hse2.access_management import add_hse2_wrapper, list_hse2_wrappers, remove_hse2_wrapper, rewrap_hse2_wrapper
from .hse2.keyfile_safety import keyfile_colocation_warning
from .hse2.workflows import read_keyfile_bytes, read_secret_text_file, validate_hse2_wrapper_policy

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

    add_parser = subparsers.add_parser("add", help="Add an unlock wrapper after authenticating the existing container.")
    add_parser.add_argument("--input", required=True)
    add_parser.add_argument("--output", required=True)
    add_parser.add_argument("--wrapper-id", required=True)
    add_parser.add_argument("--new-password-file")
    add_parser.add_argument("--new-keyfile")
    add_parser.add_argument("--new-dpapi", action="store_true", help="Use a Windows user-bound DPAPI wrapper; keep an independent recovery wrapper.")
    add_parser.add_argument("--new-profile", default="hardened", choices=["compatible", "hardened", "paranoid"])
    add_parser.add_argument("--new-label")
    add_parser.add_argument("--password-file")
    add_parser.add_argument("--keyfile")
    add_parser.add_argument("--dpapi", action="store_true")
    add_parser.add_argument("--overwrite", action="store_true")
    add_parser.add_argument("--compact", action="store_true")

    rewrap_parser = subparsers.add_parser("rewrap", help="Replace an existing wrapper atomically without rewriting the encrypted body.")
    rewrap_parser.add_argument("--input", required=True)
    rewrap_parser.add_argument("--output", required=True)
    rewrap_parser.add_argument("--wrapper-id", required=True, help="Existing wrapper id to replace.")
    rewrap_parser.add_argument("--new-wrapper-id", help="Replacement wrapper id. Defaults to --wrapper-id.")
    rewrap_parser.add_argument("--new-password-file")
    rewrap_parser.add_argument("--new-keyfile")
    rewrap_parser.add_argument("--new-dpapi", action="store_true", help="Use a Windows user-bound DPAPI wrapper; keep an independent recovery wrapper.")
    rewrap_parser.add_argument("--new-profile", default="hardened", choices=["compatible", "hardened", "paranoid"])
    rewrap_parser.add_argument("--new-label")
    rewrap_parser.add_argument("--password-file", help="Existing password used to authenticate the source.")
    rewrap_parser.add_argument("--keyfile", help="Existing keyfile used to authenticate the source.")
    rewrap_parser.add_argument("--dpapi", action="store_true", help="Allow Windows DPAPI while authenticating the source.")
    rewrap_parser.add_argument("--overwrite", action="store_true")
    rewrap_parser.add_argument("--compact", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        warning = _keyfile_colocation_warning_for_args(args)
        if warning:
            print(f"hse2-wrapper: warning: {warning}", file=sys.stderr)
        if args.command == "list":
            summary = _run_list(args)
        elif args.command == "remove":
            summary = _run_remove(args)
        elif args.command == "add":
            summary = run_add(args)
        elif args.command == "rewrap":
            summary = _run_rewrap(args)
        else:  # pragma: no cover - argparse enforces command choices
            raise HSE2ModelError(f"unsupported command: {args.command}")
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-wrapper: {exc}", file=sys.stderr)
        return 2
    if args.command in {"add", "rewrap"} and args.new_dpapi:
        summary["dpapi_recovery_warning"] = DPAPI_WRAPPER_PORTABILITY_WARNING
        print(f"hse2-wrapper: DPAPI recovery warning: {DPAPI_WRAPPER_PORTABILITY_WARNING}", file=sys.stderr)
    print(_format_json(summary, compact=bool(args.compact)))
    return 0


def _keyfile_colocation_warning_for_args(args: argparse.Namespace) -> str | None:
    if args.command == "list":
        return None
    keyfiles = [getattr(args, "keyfile", None), getattr(args, "new_keyfile", None)]
    containers = [args.input, args.output]
    return keyfile_colocation_warning(keyfiles, containers)


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


def run_add(args: argparse.Namespace) -> dict[str, Any]:
    """Add a wrapper using the shared CLI namespace contract."""

    input_path = Path(args.input)
    output_path = Path(args.output)
    _validate_container_path(input_path, field_name="input")
    _validate_container_path(output_path, field_name="output")
    new_password = read_secret_text_file(args.new_password_file) if args.new_password_file else None
    new_keyfile_bytes = read_keyfile_bytes(args.new_keyfile) if args.new_keyfile else None
    validate_hse2_wrapper_policy(
        profile_name=args.new_profile,
        has_password=bool(new_password),
        has_keyfile=new_keyfile_bytes is not None,
        use_dpapi=bool(args.new_dpapi),
    )
    add_hse2_wrapper(
        input_path, output_path, wrapper_id=args.wrapper_id,
        new_password=new_password,
        new_keyfile_bytes=new_keyfile_bytes,
        unlock_password=read_secret_text_file(args.password_file) if args.password_file else None,
        unlock_keyfile_bytes=read_keyfile_bytes(args.keyfile) if args.keyfile else None,
        allow_dpapi=bool(args.dpapi), new_wrapper_dpapi=bool(args.new_dpapi),
        profile_name=args.new_profile, label=args.new_label, overwrite=bool(args.overwrite),
    )
    listed = list_hse2_wrappers(output_path)
    return {"command": "hse2-wrapper-add", "experimental": True, "container_written": True,
            "output_path": str(output_path), "wrapper_id": args.wrapper_id,
            "wrapper_count": len(listed.wrappers), "format_version": listed.format_version}


def _run_rewrap(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    output_path = Path(args.output)
    _validate_container_path(input_path, field_name="input")
    _validate_container_path(output_path, field_name="output")
    wrapper_id = args.new_wrapper_id or args.wrapper_id
    return rewrap_hse2_wrapper(
        input_path, output_path,
        replaced_wrapper_id=args.wrapper_id,
        new_wrapper_id=wrapper_id,
        new_password=read_secret_text_file(args.new_password_file) if args.new_password_file else None,
        new_keyfile_bytes=read_keyfile_bytes(args.new_keyfile) if args.new_keyfile else None,
        unlock_password=read_secret_text_file(args.password_file) if args.password_file else None,
        unlock_keyfile_bytes=read_keyfile_bytes(args.keyfile) if args.keyfile else None,
        allow_dpapi=bool(args.dpapi),
        new_wrapper_dpapi=bool(args.new_dpapi),
        profile_name=args.new_profile,
        label=args.new_label,
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
