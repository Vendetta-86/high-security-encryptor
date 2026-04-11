from pathlib import Path
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from high_security_encryptor.batch_decryption import decrypt_batch_files
from high_security_encryptor.batch_workflow import encrypt_batch_files
from high_security_encryptor.password_sources import PasswordResolver
from high_security_encryptor.runtime_password_plan import RuntimePasswordPlan, resolve_password_plan_from_template


class RuntimePasswordPlanTests(unittest.TestCase):
    def test_resolve_password_plan_from_template_prefers_encrypted_name(self) -> None:
        """按密文名映射的规则应优先于按源文件名映射。"""

        template_payload = {
            "kind": "template",
            "rows": [
                {
                    "source_name": "a.txt",
                    "encrypted_name": "a.txt.hse",
                    "password": "",
                }
            ],
        }
        resolver = PasswordResolver(
            environment={"ENC_SECRET": "enc-pass", "SRC_SECRET": "src-pass"},
            prompt_callback=lambda prompt: "",
            file_reader=lambda path: "",
            command_runner=lambda argv: "",
        )
        mapping = resolve_password_plan_from_template(
            template_payload,
            resolver,
            RuntimePasswordPlan(
                by_encrypted_name={"a.txt.hse": {"type": "env", "name": "ENC_SECRET"}},
                by_source_name={"a.txt": {"type": "env", "name": "SRC_SECRET"}},
            ),
        )
        self.assertEqual(mapping["a.txt.hse"], "enc-pass")

    def test_decrypt_batch_files_can_use_template_runtime_password_plan_without_password_table(self) -> None:
        """顶层解密应能在 manifest+template+运行时计划下工作。"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            plain_source = temp_root / "note.txt"
            plain_source.write_text("runtime plan secret", encoding="utf-8")

            encrypted_batch = encrypt_batch_files(
                [plain_source],
                {plain_source: "plain-pass"},
                metadata_password="meta-pass",
                output_dir=temp_root / "encrypted",
                batch_id="runtime-plan-batch",
            )

            resolver = PasswordResolver(
                environment={"RUNTIME_SECRET": "plain-pass"},
                prompt_callback=lambda prompt: "",
                file_reader=lambda path: "",
                command_runner=lambda argv: "",
            )

            result = decrypt_batch_files(
                encrypted_files=encrypted_batch.encrypted_files,
                manifest_path=encrypted_batch.manifest_path,
                password_table_path=None,
                template_path=encrypted_batch.template_path,
                metadata_password="meta-pass",
                output_dir=temp_root / "decrypted",
                runtime_password_plan=RuntimePasswordPlan(
                    by_encrypted_name={"note.txt.hse": {"type": "env", "name": "RUNTIME_SECRET"}},
                    by_source_name={},
                ),
                password_resolver=resolver,
            )

            self.assertEqual(len(result.decrypted_files), 1)
            self.assertEqual(
                result.decrypted_files[0].decrypted_path.read_text(encoding="utf-8"),
                "runtime plan secret",
            )
            self.assertEqual(result.password_table_payload["records"], [])


if __name__ == "__main__":
    unittest.main()
