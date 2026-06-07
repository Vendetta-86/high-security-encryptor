import contextlib
from dataclasses import replace
import io
import json
import tempfile
from pathlib import Path
import unittest

from high_security_encryptor.hse2 import (
    HSE2UnlockFactors,
    attach_header_auth_tag,
    read_hse2_container,
    unlock_first_matching_wrapper,
    write_hse2_container,
)
from high_security_encryptor.hse2.wrapper_builders import build_password_wrapper
from high_security_encryptor.hse2_access_cli import main as access_main
from high_security_encryptor.hse2_create_cli import main as create_main
from high_security_encryptor.hse2_open_cli import main as open_main
from high_security_encryptor.hse2_wrapper_cli import main as wrapper_main

DESTROY_CONFIRMATION = "I UNDERSTAND THIS WILL MAKE THE DATA PERMANENTLY UNRECOVERABLE"
TEST_WRAPPER_PASSWORD = "extra-password"  # pragma: allowlist secret


class HSE2AccessManagementCliTests(unittest.TestCase):
    def test_wrapper_cli_lists_safe_wrapper_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = _create_fixture(Path(temp_dir))

            payload = _list_wrappers(fixture.container)

            self.assertEqual(payload["command"], "hse2-wrapper list")
            self.assertFalse(payload["access_destroyed"])
            self.assertEqual(payload["wrapper_count"], 1)
            self.assertEqual(payload["wrappers"][0]["id"], "keyfile-1")
            self.assertEqual(payload["wrappers"][0]["type"], "keyfile")
            self.assertEqual(payload["wrappers"][0]["label"], "keyfile")

    def test_wrapper_cli_removes_selected_wrapper_after_unlock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            fixture = _create_fixture(base)
            _append_password_wrapper(fixture.container, fixture.keyfile)

            before = _list_wrappers(fixture.container)
            self.assertEqual(before["wrapper_count"], 2)

            removed_payload = _remove_wrapper(
                fixture.container,
                fixture.removed_container,
                wrapper_id="password-2",
                keyfile=fixture.keyfile,
            )

            self.assertTrue(removed_payload["container_written"])
            self.assertEqual(removed_payload["removed_wrapper_id"], "password-2")
            self.assertEqual(removed_payload["remaining_wrapper_count"], 1)
            self.assertEqual(removed_payload["unlocked_wrapper_type"], "keyfile")

            after = _list_wrappers(fixture.removed_container)
            self.assertEqual(after["wrapper_count"], 1)
            self.assertEqual(after["wrappers"][0]["id"], "keyfile-1")
            self.assertEqual(_open_container(fixture.removed_container, fixture.keyfile, fixture.restored_dir), 0)
            self.assertEqual((fixture.restored_dir / "root" / "a.txt").read_bytes(), b"abc")

    def test_wrapper_cli_refuses_to_remove_last_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = _create_fixture(Path(temp_dir))
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = wrapper_main([
                    "remove",
                    "--input",
                    str(fixture.container),
                    "--output",
                    str(fixture.removed_container),
                    "--wrapper-id",
                    "keyfile-1",
                    "--keyfile",
                    str(fixture.keyfile),
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("cannot remove the last wrapper", stderr.getvalue())
            self.assertFalse(fixture.removed_container.exists())

    def test_access_cli_destroy_requires_exact_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = _create_fixture(Path(temp_dir))
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = access_main([
                    "destroy",
                    "--input",
                    str(fixture.container),
                    "--output",
                    str(fixture.destroyed_container),
                    "--confirm",
                    "wrong phrase",
                ])

            self.assertEqual(exit_code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("confirmation phrase", stderr.getvalue())
            self.assertFalse(fixture.destroyed_container.exists())

    def test_access_cli_destroy_removes_wrappers_and_marks_container(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = _create_fixture(Path(temp_dir))

            payload = _destroy_access(fixture.container, fixture.destroyed_container)

            self.assertTrue(payload["container_written"])
            self.assertTrue(payload["access_destroyed"])
            self.assertEqual(payload["removed_wrapper_count"], 1)

            listed = _list_wrappers(fixture.destroyed_container)
            self.assertTrue(listed["access_destroyed"])
            self.assertEqual(listed["wrapper_count"], 0)
            self.assertEqual(_open_container(fixture.destroyed_container, fixture.keyfile, fixture.restored_dir), 2)


class _Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.root = base / "root"
        self.keyfile = base / "archive.key"
        self.container = base / "archive.hse2"
        self.removed_container = base / "removed.hse2"
        self.destroyed_container = base / "destroyed.hse2"
        self.restored_dir = base / "restored"


def _create_fixture(base: Path) -> _Fixture:
    fixture = _Fixture(base)
    fixture.root.mkdir()
    (fixture.root / "a.txt").write_bytes(b"abc")
    fixture.keyfile.write_bytes(b"k" * 32)

    with contextlib.redirect_stdout(io.StringIO()):
        create_exit = create_main([
            "--root",
            str(fixture.root),
            "--output",
            str(fixture.container),
            "--keyfile",
            str(fixture.keyfile),
            "--chunk-size",
            "4",
        ])
    if create_exit != 0:
        raise AssertionError(f"fixture create failed: {create_exit}")
    return fixture


def _append_password_wrapper(container_path: Path, keyfile_path: Path) -> None:
    container = read_hse2_container(container_path)
    keys = unlock_first_matching_wrapper(
        container.header.wrappers,
        factors=HSE2UnlockFactors(keyfile_bytes=keyfile_path.read_bytes(), allow_dpapi=False),
    )
    extra_wrapper = build_password_wrapper(
        wrapper_id="password-2",
        created_utc=container.header.created_utc,
        password=TEST_WRAPPER_PASSWORD,
        profile_name="compatible",
        dek=keys.dek,
        mek=keys.mek,
        label="extra password",
    ).record
    new_header = replace(
        container.header,
        wrappers=container.header.wrappers + (extra_wrapper,),
        header_auth_tag=None,
    )
    new_header = attach_header_auth_tag(new_header, mek=keys.mek)
    write_hse2_container(
        container_path,
        header=new_header,
        manifest=container.manifest,
        payload_chunks=container.payload_chunks,
        overwrite=True,
    )


def _list_wrappers(container: Path) -> dict[str, object]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = wrapper_main(["list", "--input", str(container)])
    if exit_code != 0:
        raise AssertionError(f"wrapper list failed: {exit_code}")
    return json.loads(stdout.getvalue())


def _remove_wrapper(container: Path, output: Path, *, wrapper_id: str, keyfile: Path) -> dict[str, object]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = wrapper_main([
            "remove",
            "--input",
            str(container),
            "--output",
            str(output),
            "--wrapper-id",
            wrapper_id,
            "--keyfile",
            str(keyfile),
        ])
    if exit_code != 0:
        raise AssertionError(f"wrapper remove failed: {exit_code}")
    return json.loads(stdout.getvalue())


def _destroy_access(container: Path, output: Path) -> dict[str, object]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = access_main([
            "destroy",
            "--input",
            str(container),
            "--output",
            str(output),
            "--confirm",
            DESTROY_CONFIRMATION,
        ])
    if exit_code != 0:
        raise AssertionError(f"access destroy failed: {exit_code}")
    return json.loads(stdout.getvalue())


def _open_container(container: Path, keyfile: Path, output_dir: Path) -> int:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        return open_main([
            "--input",
            str(container),
            "--output-dir",
            str(output_dir),
            "--keyfile",
            str(keyfile),
        ])


if __name__ == "__main__":
    unittest.main()
