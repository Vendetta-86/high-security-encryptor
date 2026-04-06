import io
import os
import tempfile
import unittest
import zipfile

import aes_gcm_merged_final as app


class DummyVar:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class DummyRoot:
    def __init__(self):
        self.clipboard = None
        self.after_calls = {}
        self.next_job_id = 1

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, value):
        self.clipboard = value

    def after(self, delay_ms, callback):
        job_id = f"job-{self.next_job_id}"
        self.next_job_id += 1
        self.after_calls[job_id] = (delay_ms, callback)
        return job_id

    def after_cancel(self, job_id):
        self.after_calls.pop(job_id, None)


class ZipSecurityTests(unittest.TestCase):
    def test_safe_extract_zip_blocks_parent_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = os.path.join(temp_dir, "evil.zip")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../evil.txt", "blocked")

            with zipfile.ZipFile(archive_path, "r") as archive:
                with self.assertRaises(ValueError):
                    app.safe_extract_zip(archive, os.path.join(temp_dir, "out"))

    def test_safe_extract_zip_extracts_normal_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = os.path.join(temp_dir, "ok.zip")
            output_dir = os.path.join(temp_dir, "out")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("nested/file.txt", "hello")

            with zipfile.ZipFile(archive_path, "r") as archive:
                app.safe_extract_zip(archive, output_dir)

            with open(os.path.join(output_dir, "nested", "file.txt"), "r", encoding="utf-8") as file_obj:
                self.assertEqual(file_obj.read(), "hello")

    def test_build_folder_package_encrypts_marked_inner_file_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = os.path.join(temp_dir, "folder")
            os.makedirs(folder_path, exist_ok=True)
            normal_file = os.path.join(folder_path, "plain.txt")
            secret_file = os.path.join(folder_path, "secret.txt")
            with open(normal_file, "w", encoding="utf-8") as file_obj:
                file_obj.write("plain")
            with open(secret_file, "w", encoding="utf-8") as file_obj:
                file_obj.write("secret")

            archive_path = app.build_folder_package(
                folder_path,
                "main-password",
                individually_encrypt_files={secret_file},
            )

            with zipfile.ZipFile(archive_path, "r") as archive:
                names = set(archive.namelist())

            self.assertIn("folder/plain.txt", names)
            self.assertIn("folder/secret.txt.gcm", names)
            self.assertNotIn("folder/secret.txt", names)

    def test_build_folder_package_uses_child_specific_password_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = os.path.join(temp_dir, "folder")
            os.makedirs(folder_path, exist_ok=True)
            secret_file = os.path.join(folder_path, "secret.txt")
            with open(secret_file, "w", encoding="utf-8") as file_obj:
                file_obj.write("secret")

            archive_path = app.build_folder_package(
                folder_path,
                "outer-password",
                individually_encrypt_files={secret_file},
                child_password_map={secret_file: "child-password"},
            )

            with zipfile.ZipFile(archive_path, "r") as archive:
                secret_blob = archive.read("folder/secret.txt.gcm")
                manifest_blob = archive.read("folder/batch_manifest.json.gcm")

            self.assertEqual(app.decrypt_bytes(secret_blob, "child-password").decode("utf-8"), "secret")
            manifest = app.load_manifest_from_blob(manifest_blob, "outer-password")
            self.assertEqual(manifest["entries"][0]["encrypted_name"], "folder/secret.txt.gcm")


class ManifestSecurityTests(unittest.TestCase):
    def test_manifest_is_saved_encrypted_and_round_trips(self):
        manifest = {
            "version": 1,
            "mode": "individual_batch",
            "groups": [{"group_id": "g1", "label": "密码组1", "verifier": app.build_password_verifier("pw")}],
            "entries": [{"encrypted_name": "a.txt.gcm", "group_id": "g1"}],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "manifest.json.gcm")
            app.save_manifest(manifest, path, "main-password")

            with open(path, "rb") as file_obj:
                raw = file_obj.read()

            self.assertNotIn(b"encrypted_name", raw)
            self.assertEqual(app.load_manifest(path, password="main-password"), manifest)

    def test_find_manifest_for_files_supports_encrypted_manifest(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            encrypted_path = os.path.join(temp_dir, "demo.txt.gcm")
            with open(encrypted_path, "wb") as file_obj:
                file_obj.write(b"x")

            manifest = {
                "version": 1,
                "mode": "individual_batch",
                "groups": [{"group_id": "g1", "label": "密码组1", "verifier": app.build_password_verifier("pw")}],
                "entries": [{"encrypted_name": "demo.txt.gcm", "group_id": "g1"}],
            }
            manifest_path = app.build_manifest_path([encrypted_path])
            app.save_manifest(manifest, manifest_path, "main-password")

            found = app.find_manifest_for_files([encrypted_path], password="main-password")
            self.assertEqual(found, manifest_path)


class PrivacyStateTests(unittest.TestCase):
    def test_clear_sensitive_state_wipes_password_related_fields(self):
        instance = app.AESGCMApp.__new__(app.AESGCMApp)
        instance.password_var = DummyVar("secret")
        instance.bundle_password_var = DummyVar("bundle")
        instance.selected_files = ["a.txt", "b.txt"]
        instance.file_password_overrides = {"a.txt": "one", "b.txt": "two"}
        instance.file_password_sources = {"a.txt": "manual", "b.txt": "auto"}
        instance.password_table_imported = True

        app.AESGCMApp._clear_sensitive_state(instance)

        self.assertEqual(instance.password_var.get(), "")
        self.assertEqual(instance.bundle_password_var.get(), "")
        self.assertEqual(instance.file_password_overrides, {})
        self.assertEqual(instance.file_password_sources, {"a.txt": "main", "b.txt": "main"})
        self.assertFalse(instance.password_table_imported)

    def test_copy_sensitive_to_clipboard_schedules_auto_clear(self):
        instance = app.AESGCMApp.__new__(app.AESGCMApp)
        instance.root = DummyRoot()
        instance.status_var = DummyVar("")
        instance.clipboard_clear_job = None

        app.AESGCMApp._copy_sensitive_to_clipboard(instance, "secret", "copied")

        self.assertEqual(instance.root.clipboard, "secret")
        self.assertEqual(instance.status_var.get(), "copied")
        self.assertIsNotNone(instance.clipboard_clear_job)
        self.assertEqual(len(instance.root.after_calls), 1)


class PathBehaviorTests(unittest.TestCase):
    def test_get_source_encrypted_output_path_uses_zip_gcm_for_folders(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = os.path.join(temp_dir, "demo")
            file_path = os.path.join(temp_dir, "demo.txt")
            os.makedirs(folder_path, exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as file_obj:
                file_obj.write("x")

            self.assertTrue(app.get_source_encrypted_output_path(folder_path).endswith(".zip.gcm"))
            self.assertTrue(app.get_source_encrypted_output_path(file_path).endswith(".txt.gcm"))


class TemplateImportTests(unittest.TestCase):
    def test_import_password_template_file_sets_folder_child_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = os.path.join(temp_dir, "folder")
            os.makedirs(folder_path, exist_ok=True)
            child_path = os.path.join(folder_path, "child.txt")
            with open(child_path, "w", encoding="utf-8") as file_obj:
                file_obj.write("x")

            template_path = os.path.join(temp_dir, "template.csv")
            with open(template_path, "w", encoding="utf-8-sig", newline="") as file_obj:
                file_obj.write("source_file,source_scope,source_type,password\n")
                file_obj.write("child.txt,folder,folder_child,child-password\n")

            instance = app.AESGCMApp.__new__(app.AESGCMApp)
            instance.selected_files = [folder_path]
            instance.file_password_overrides = {}
            instance.file_password_sources = {}
            instance.folder_individual_encrypt_files = {}
            instance.folder_child_password_overrides = {}
            instance.folder_child_password_sources = {}

            imported = app.AESGCMApp._import_password_template_file(instance, template_path)

            self.assertEqual(imported, 1)
            self.assertIn(child_path, instance.folder_individual_encrypt_files[folder_path])
            self.assertEqual(instance.folder_child_password_overrides[child_path], "child-password")

    def test_build_template_password_rows_can_limit_folder_children_to_marked_items(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder_path = os.path.join(temp_dir, "folder")
            os.makedirs(folder_path, exist_ok=True)
            marked_child = os.path.join(folder_path, "marked.txt")
            plain_child = os.path.join(folder_path, "plain.txt")
            for path in (marked_child, plain_child):
                with open(path, "w", encoding="utf-8") as file_obj:
                    file_obj.write("x")

            rows = app.build_template_password_rows(
                [folder_path],
                {folder_path: "root-password"},
                "individual",
                folder_individual_encrypt_map={folder_path: {marked_child}},
                folder_child_password_map={marked_child: "child-password"},
                export_marked_folder_children_only=True,
            )

            child_rows = [row for row in rows if row["source_type"] == "folder_child"]
            self.assertEqual(len(child_rows), 1)
            self.assertEqual(child_rows[0]["source_file"], "marked.txt")


if __name__ == "__main__":
    unittest.main()
