from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from high_security_encryptor.hse2.container_v5_credentials import unlock_v5_credentials
from high_security_encryptor.hse2.container_v5_descriptor import open_v5_descriptor
from high_security_encryptor.hse2.container_v5_file import V5ContainerReader
from high_security_encryptor.hse2.container_v4_workflows import create_v4_archive
from high_security_encryptor.hse2.container_v5_migration import compact_v5_archive, export_v4_to_v5
from high_security_encryptor.hse2.restore_staging import _FileLock, _stage_lock_path, cleanup_stale_restore_stages
from high_security_encryptor.hse2.container_v5_workflows import (
    create_v5_archive,
    replace_v5_view,
    restore_v5_archive,
)
from high_security_encryptor.hse2.models import HSE2ModelError


class HSE2V5WorkflowTests(unittest.TestCase):
    def test_create_and_restore_two_independent_compact_views(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "primary.txt"
            empty = root / "empty.txt"
            secondary = root / "secondary.txt"
            primary.write_bytes(b"one byte")
            empty.write_bytes(b"")
            secondary.write_bytes(b"peer view")
            archive = root / "compact.hse2"

            create_v5_archive(
                output_path=archive,
                view_passwords=("primary view pass", "secondary view pass"),
                view_files=((('a.txt', primary), ('empty.txt', empty)), (('b.txt', secondary),)),
            )
            self.assertLess(archive.stat().st_size, 1024 * 1024)

            restored_primary = restore_v5_archive(
                input_path=archive, password="primary view pass", output_dir=root / "primary-out",  # pragma: allowlist secret
            )
            restored_secondary = restore_v5_archive(
                input_path=archive, password="secondary view pass", output_dir=root / "secondary-out",  # pragma: allowlist secret
            )
            self.assertEqual((restored_primary / "a.txt").read_bytes(), b"one byte")
            self.assertEqual((restored_primary / "empty.txt").read_bytes(), b"")
            self.assertEqual((restored_secondary / "b.txt").read_bytes(), b"peer view")
            self.assertFalse((restored_primary / "b.txt").exists())
            self.assertFalse((restored_secondary / "a.txt").exists())
            self.assertGreaterEqual(archive.stat().st_size, 234)

    def test_replace_one_view_preserves_peer_and_original_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "primary.txt"
            secondary = root / "secondary.txt"
            replacement = root / "replacement.txt"
            primary.write_bytes(b"old primary")
            secondary.write_bytes(b"unchanged peer")
            replacement.write_bytes(b"new primary data")
            archive = root / "before.hse2"
            updated = root / "after.hse2"
            create_v5_archive(
                output_path=archive,
                view_passwords=("primary view pass", "secondary view pass"),
                view_files=((('primary.txt', primary),), (('secondary.txt', secondary),)),
            )
            original_digest = hashlib.sha256(archive.read_bytes()).hexdigest()

            replace_v5_view(
                input_path=archive,
                output_path=updated,
                password="primary view pass",  # pragma: allowlist secret
                view_files=(('replacement.txt', replacement),),
            )
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), original_digest)
            self.assertEqual(
                (restore_v5_archive(input_path=updated, password="primary view pass",  # pragma: allowlist secret
                                    output_dir=root / "updated-primary") / "replacement.txt").read_bytes(),
                b"new primary data",
            )
            self.assertEqual(
                (restore_v5_archive(input_path=updated, password="secondary view pass",  # pragma: allowlist secret
                                    output_dir=root / "updated-secondary") / "secondary.txt").read_bytes(),
                b"unchanged peer",
            )
            self.assertEqual(
                (restore_v5_archive(input_path=archive, password="primary view pass",  # pragma: allowlist secret
                                    output_dir=root / "original-primary") / "primary.txt").read_bytes(),
                b"old primary",
            )

    def test_tampered_record_fails_without_publishing_restore_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_bytes(b"authenticated payload")
            archive = root / "archive.hse2"
            create_v5_archive(
                output_path=archive,
                view_passwords=("primary view pass", "secondary view pass"),
                view_files=((('source.txt', source),), ()),
            )
            damaged = root / "damaged.hse2"
            damaged.write_bytes(archive.read_bytes())
            with V5ContainerReader(damaged) as reader:
                slot, root_key = unlock_v5_credentials("primary view pass", reader.header.credential_slots,
                                                       archive_id=reader.header.archive_id)
                generation, blob = reader.read_descriptor(slot)
                descriptor = open_v5_descriptor(root_key=root_key, archive_id=reader.header.archive_id,
                                                slot=slot, generation=generation,
                                                offset=reader.footer.views[slot].offset, blob=blob)
                record_offset = descriptor.files[0].chunks[0].offset
            with damaged.open("r+b") as file_obj:
                file_obj.seek(record_offset + 60)
                byte = file_obj.read(1)
                file_obj.seek(record_offset + 60)
                file_obj.write(bytes([byte[0] ^ 1]))
            output = root / "must-not-exist"
            with self.assertRaisesRegex(HSE2ModelError, "authentication or restore failed"):
                restore_v5_archive(input_path=damaged, password="primary view pass", output_dir=output)  # pragma: allowlist secret
            self.assertFalse(output.exists())

    def test_create_refuses_to_overwrite_an_input_even_with_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "primary.txt"
            secondary = root / "secondary.txt"
            primary.write_bytes(b"keep this input")
            secondary.write_bytes(b"peer")
            with self.assertRaisesRegex(HSE2ModelError, "must not overwrite an input"):
                create_v5_archive(
                    output_path=primary,
                    view_passwords=("primary view pass", "secondary view pass"),
                    view_files=((('primary.txt', primary),), (('secondary.txt', secondary),)),
                    overwrite=True,
                )
            self.assertEqual(primary.read_bytes(), b"keep this input")

    def test_injected_record_write_failure_keeps_targets_unpublished(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_bytes(b"atomic output test")
            archive = root / "source.hse2"
            create_v5_archive(
                output_path=archive,
                view_passwords=("primary view pass", "secondary view pass"),
                view_files=((('source.txt', source),), ()),
            )
            original_digest = hashlib.sha256(archive.read_bytes()).digest()
            create_target = root / "failed-create.hse2"

            with patch("high_security_encryptor.hse2.container_v5_workflows.seal_v5_record",
                       side_effect=OSError("injected record write failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    create_v5_archive(
                        output_path=create_target,
                        view_passwords=("primary new pass", "secondary new pass"),
                        view_files=((('source.txt', source),), ()),
                    )
            self.assertFalse(create_target.exists())

            replace_target = root / "existing-target.hse2"
            replace_target.write_bytes(b"previous output")
            with patch("high_security_encryptor.hse2.container_v5_workflows.seal_v5_record",
                       side_effect=OSError("injected record write failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    replace_v5_view(
                        input_path=archive, output_path=replace_target, password="primary view pass",  # pragma: allowlist secret
                        view_files=(("new.txt", source),), overwrite=True,
                    )

            self.assertEqual(replace_target.read_bytes(), b"previous output")
            self.assertEqual(hashlib.sha256(archive.read_bytes()).digest(), original_digest)
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_injected_flush_failures_preserve_create_replace_restore_and_migration_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "primary.txt"
            secondary = root / "secondary.txt"
            primary.write_bytes(b"primary flush test")
            secondary.write_bytes(b"secondary flush test")
            passwords = ("primary view pass", "secondary view pass")
            archive = root / "source-v5.hse2"
            create_v5_archive(
                output_path=archive, view_passwords=passwords,
                view_files=((('primary.txt', primary),), (('secondary.txt', secondary),)),
            )
            source_digest = hashlib.sha256(archive.read_bytes()).digest()

            failed_create = root / "failed-create.hse2"
            with patch("high_security_encryptor.hse2.container_v5_workflows.flush_file",
                       side_effect=OSError("injected flush failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    create_v5_archive(
                        output_path=failed_create,
                        view_passwords=("new primary", "new secondary"),
                        view_files=((('primary.txt', primary),), (('secondary.txt', secondary),)),
                    )
            self.assertFalse(failed_create.exists())

            replace_target = root / "replace-target.hse2"
            replace_target.write_bytes(b"prior replace output")
            with patch("high_security_encryptor.hse2.container_v5_workflows.flush_file",
                       side_effect=OSError("injected flush failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    replace_v5_view(
                        input_path=archive, output_path=replace_target, password=passwords[0],
                        view_files=(("updated.txt", primary),), overwrite=True,
                    )
            self.assertEqual(replace_target.read_bytes(), b"prior replace output")

            restore_target = root / "failed-restore"
            with patch("high_security_encryptor.hse2.container_v5_workflows.flush_file",
                       side_effect=OSError("injected flush failure")):
                with self.assertRaises(HSE2ModelError):
                    restore_v5_archive(input_path=archive, password=passwords[0], output_dir=restore_target)
            self.assertFalse(restore_target.exists())
            self.assertEqual(list(root.glob(".failed-restore.v5-restore-*")), [])

            compact_target = root / "compact-target.hse2"
            compact_target.write_bytes(b"prior compact output")
            with patch("high_security_encryptor.hse2.container_v5_migration.flush_file",
                       side_effect=OSError("injected flush failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    compact_v5_archive(
                        input_path=archive, output_path=compact_target, view_passwords=passwords, overwrite=True,
                    )
            self.assertEqual(compact_target.read_bytes(), b"prior compact output")

            legacy_v4 = root / "legacy-v4.hse2"
            create_v4_archive(
                output_path=legacy_v4, view_passwords=passwords,
                view_files=((('primary.txt', primary),), (('secondary.txt', secondary),)),
                capacity_records=2,
            )
            export_target = root / "export-target.hse2"
            export_target.write_bytes(b"prior export output")
            with patch("high_security_encryptor.hse2.container_v5_migration.flush_file",
                       side_effect=OSError("injected flush failure")):
                with self.assertRaisesRegex(OSError, "injected"):
                    export_v4_to_v5(
                        input_path=legacy_v4, output_path=export_target,
                        view_passwords=passwords, overwrite=True,
                    )
            self.assertEqual(export_target.read_bytes(), b"prior export output")
            self.assertEqual(hashlib.sha256(archive.read_bytes()).digest(), source_digest)
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_crashed_restore_staging_is_cleaned_without_touching_an_active_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_bytes(b"crash recovery payload")
            archive = root / "archive.hse2"
            create_v5_archive(
                output_path=archive,
                view_passwords=("primary view pass", "secondary view pass"),
                view_files=((('source.txt', source),), ()),
            )
            target = root / "restored"
            marker = root / "child-staging.marker"
            child_script = """
from pathlib import Path
import sys
import time
import high_security_encryptor.hse2.container_v5_workflows as workflows

archive, password, output_dir, marker = sys.argv[1:]
original = workflows.open_v5_record
def pause_after_stage(**kwargs):
    Path(marker).write_text("ready", encoding="ascii")
    time.sleep(60)
    return original(**kwargs)
workflows.open_v5_record = pause_after_stage
workflows.restore_v5_archive(input_path=archive, password=password, output_dir=output_dir)
"""
            process = subprocess.Popen(
                [sys.executable, "-c", child_script, str(archive), "primary view pass", str(target), str(marker)],
                cwd=Path.cwd(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 15
                while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not marker.exists():
                    self.fail(f"restore worker did not reach plaintext staging; exit code={process.poll()}")

                # A second restore must leave the first worker's leased staging directory alone.
                restore_v5_archive(input_path=archive, password="primary view pass", output_dir=target)  # pragma: allowlist secret
                active_stages = list(root.glob(".restored.v5-restore-*"))
                self.assertEqual(len(active_stages), 1)
                self.assertEqual((target / "source.txt").read_bytes(), b"crash recovery payload")

                process.terminate()
                process.wait(timeout=5)
                stale_stage = active_stages[0]
                probe = _FileLock(_stage_lock_path(stale_stage), blocking=False)
                deadline = time.monotonic() + 2
                while True:
                    try:
                        probe.acquire()
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            self.fail("restore stage lease stayed locked after worker exit")
                        time.sleep(0.02)
                    except OSError as exc:
                        self.fail(f"could not verify restore stage lease release: {exc}")
                    else:
                        probe.release()
                        break
                with self.assertRaisesRegex(HSE2ModelError, "restore output already exists"):
                    restore_v5_archive(input_path=archive, password="primary view pass", output_dir=target)  # pragma: allowlist secret
                self.assertEqual(list(root.glob(".restored.v5-restore-*")), [])
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                cleanup_stale_restore_stages(target)

    def test_compaction_rewrites_only_current_views_and_reclaims_stale_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_primary = root / "old-primary.txt"
            new_primary = root / "new-primary.txt"
            peer = root / "peer.txt"
            old_primary.write_bytes(b"old payload" * 50)
            new_primary.write_bytes(b"new payload")
            peer.write_bytes(b"peer stays")
            source_archive = root / "source.hse2"
            replaced_archive = root / "replaced.hse2"
            compacted_archive = root / "compacted.hse2"
            passwords = ("primary view pass", "secondary view pass")
            create_v5_archive(
                output_path=source_archive, view_passwords=passwords,
                view_files=((('primary.txt', old_primary),), (('peer.txt', peer),)),
            )
            replace_v5_view(
                input_path=source_archive, output_path=replaced_archive, password=passwords[0],
                view_files=(('primary.txt', new_primary),),
            )
            compact_v5_archive(
                input_path=replaced_archive, output_path=compacted_archive, view_passwords=passwords,
            )
            self.assertLess(compacted_archive.stat().st_size, replaced_archive.stat().st_size)
            self.assertEqual(
                (restore_v5_archive(input_path=compacted_archive, password=passwords[0],
                                    output_dir=root / "compact-primary") / "primary.txt").read_bytes(),
                b"new payload",
            )
            self.assertEqual(
                (restore_v5_archive(input_path=compacted_archive, password=passwords[1],
                                    output_dir=root / "compact-peer") / "peer.txt").read_bytes(),
                b"peer stays",
            )

    def test_v4_export_requires_both_views_and_preserves_the_v4_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "primary.txt"
            secondary = root / "secondary.txt"
            primary.write_bytes(b"v4 primary")
            secondary.write_bytes(b"v4 secondary")
            source_archive = root / "legacy-v4.hse2"
            output_archive = root / "exported-v5.hse2"
            passwords = ("primary view pass", "secondary view pass")
            create_v4_archive(
                output_path=source_archive, view_passwords=passwords,
                view_files=((('primary.txt', primary),), (('secondary.txt', secondary),)),
                capacity_records=2,
            )
            source_digest = hashlib.sha256(source_archive.read_bytes()).hexdigest()
            export_v4_to_v5(input_path=source_archive, output_path=output_archive,
                            view_passwords=passwords)
            self.assertLess(output_archive.stat().st_size, 1024 * 1024)
            self.assertEqual(hashlib.sha256(source_archive.read_bytes()).hexdigest(), source_digest)
            self.assertEqual(
                (restore_v5_archive(input_path=output_archive, password=passwords[0],
                                    output_dir=root / "export-primary") / "primary.txt").read_bytes(),
                b"v4 primary",
            )
            self.assertEqual(
                (restore_v5_archive(input_path=output_archive, password=passwords[1],
                                    output_dir=root / "export-secondary") / "secondary.txt").read_bytes(),
                b"v4 secondary",
            )


if __name__ == "__main__":
    unittest.main()
