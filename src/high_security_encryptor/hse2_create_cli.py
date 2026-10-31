"""Guarded experimental HSE2 create CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .dpapi_guidance import DPAPI_WRAPPER_PORTABILITY_WARNING
from .hse2 import HSE2ModelError, build_archive_assembly_plan, build_archive_entries_from_roots
from .hse2.keyfile_safety import keyfile_colocation_warning
from .hse2.workflows import (
    create_hse2_archive,
    read_keyfile_bytes,
    read_secret_text_file,
    validate_hse2_archive,
    validate_hse2_wrapper_policy,
)

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
        help="Target .hse2 container path.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CREATE_CHUNK_SIZE,
        help=f"Payload chunk size. Defaults to {DEFAULT_CREATE_CHUNK_SIZE}.",
    )
    parser.add_argument("--format-version", type=int, choices=(2, 3), default=2, help="Container format version. Defaults to v2 for compatibility.")
    parser.add_argument(
        "--pad-last-chunk",
        action="store_true",
        help="Pad each non-empty file's final encrypted chunk to --chunk-size with random bytes; hides its exact size within one chunk.",
    )
    parser.add_argument(
        "--validate-after-create",
        action="store_true",
        help="Re-open and authenticate the completed archive without writing plaintext before reporting success.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Emit metadata-only create plan JSON without reading payload bytes or writing a container.",
    )
    parser.add_argument(
        "--password-file",
        help="UTF-8 file containing the archive password. One trailing newline is stripped.",
    )
    parser.add_argument(
        "--keyfile",
        help="Binary keyfile used to create a keyfile or password+keyfile wrapper.",
    )
    parser.add_argument(
        "--dpapi",
        action="store_true",
        help="Create a Windows DPAPI wrapper bound to the current Windows user.",
    )
    parser.add_argument(
        "--profile",
        default="hardened",
        choices=["compatible", "hardened", "paranoid"],
        help="Argon2id profile for password-backed wrappers. Defaults to hardened.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing an existing output container.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact single-line JSON to stdout.",
    )
    return parser


def main(argv: list[str] | None = None, *, password_override: str | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    if args.dry_run and args.validate_after_create:
        print("hse2-create: --validate-after-create cannot be used with --dry-run", file=sys.stderr)
        return 2
    try:
        output_path = Path(args.output)
        _validate_output_path(output_path)
        warning = keyfile_colocation_warning((args.keyfile,), (output_path,))
        if warning:
            print(f"hse2-create: warning: {warning}", file=sys.stderr)
        roots = tuple(Path(root) for root in args.root)
        if args.dry_run:
            summary = _build_dry_run_summary(args=args, roots=roots, output_path=output_path)
        else:
            if password_override is not None and args.password_file:
                raise ValueError("password override cannot be combined with --password-file")
            password = password_override if password_override is not None else (
                read_secret_text_file(args.password_file) if args.password_file else None
            )
            keyfile_bytes = read_keyfile_bytes(args.keyfile) if args.keyfile else None
            result = create_hse2_archive(
                roots=roots,
                output_path=output_path,
                password=password,
                keyfile_bytes=keyfile_bytes,
                use_dpapi=bool(args.dpapi),
                profile_name=args.profile,
                chunk_size=int(args.chunk_size),
                overwrite=bool(args.overwrite),
                container_format_version=int(args.format_version),
                pad_last_chunk=bool(args.pad_last_chunk),
            )
            summary = result.to_dict()
            if args.validate_after_create:
                try:
                    validation = validate_hse2_archive(
                        input_path=output_path,
                        password=password,
                        keyfile_bytes=keyfile_bytes,
                        allow_dpapi=bool(args.dpapi),
                    )
                    summary["post_create_validation"] = validation.to_dict()
                except (HSE2ModelError, OSError, ValueError) as exc:
                    summary["post_create_validation"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            backup_path = _recommended_header_backup_path(output_path)
            summary["header_backup_recommended"] = True
            summary["header_backup_path"] = str(backup_path)
            summary["header_backup_export_argv"] = [
                "high-security-encryptor-hse2-header-backup",
                "export",
                "--input",
                str(output_path),
                "--output",
                str(backup_path),
            ]
            if args.dpapi:
                summary["dpapi_recovery_warning"] = DPAPI_WRAPPER_PORTABILITY_WARNING
            print(
                "hse2-create: header backup recommended; export it now with: "
                f'high-security-encryptor-hse2-header-backup export --input "{output_path}" '
                f'--output "{backup_path}". It restores header metadata only and cannot recover or replace any unlock factor.',
                file=sys.stderr,
            )
            if args.dpapi:
                print(f"hse2-create: DPAPI recovery warning: {DPAPI_WRAPPER_PORTABILITY_WARNING}", file=sys.stderr)
    except (HSE2ModelError, OSError, ValueError) as exc:
        print(f"hse2-create: {exc}", file=sys.stderr)
        return 2
    print(_format_json(summary, compact=bool(args.compact)))
    if not args.dry_run and args.validate_after_create and not summary.get("post_create_validation", {}).get("ok"):
        print("hse2-create: archive was written, but post-create validation failed", file=sys.stderr)
        return 3
    return 0


def _build_dry_run_summary(*, args: argparse.Namespace, roots: tuple[Path, ...], output_path: Path) -> dict[str, Any]:
    validate_hse2_wrapper_policy(
        profile_name=args.profile,
        has_password=bool(args.password_file),
        has_keyfile=bool(args.keyfile),
        use_dpapi=bool(args.dpapi),
    )
    entries = build_archive_entries_from_roots(roots)
    summary = build_archive_assembly_plan(entries, chunk_size=int(args.chunk_size))
    summary["command"] = "hse2-create"
    summary["experimental"] = True
    summary["dry_run"] = True
    summary["container_written"] = False
    summary["root_count"] = len(roots)
    summary["roots"] = [str(root) for root in roots]
    summary["output_path"] = str(output_path)
    summary["wrapper_type"] = _dry_run_wrapper_type(args)
    summary["format_version"] = int(args.format_version)
    if bool(args.pad_last_chunk):
        summary["payload_padding"] = "last-chunk-to-chunk-size"
    return summary


def _dry_run_wrapper_type(args: argparse.Namespace) -> str:
    if bool(args.dpapi):
        return "dpapi"
    if args.password_file and args.keyfile:
        return "password_keyfile"
    if args.password_file:
        return "password"
    if args.keyfile:
        return "keyfile"
    return "none"


def _validate_output_path(path: Path) -> None:
    if path.suffix.lower() != HSE2_CONTAINER_SUFFIX:
        raise ValueError("output path must use the .hse2 suffix")


def _recommended_header_backup_path(output_path: Path) -> Path:
    return output_path.with_suffix(".hse2.header")


def _format_json(payload: dict[str, Any], *, compact: bool) -> str:
    if compact:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
