from __future__ import annotations

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_NAME = "high-security-encryptor-hse2-archive-validate"
ENTRY_SCRIPT = "pyinstaller_hse2_archive_validate_entry.py"


class WindowsExeWorkflowContractTests(unittest.TestCase):
    def test_archive_validation_helper_is_built_smoke_tested_and_packaged(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "windows-exe.yml").read_text(encoding="utf-8")
        documentation = (REPO_ROOT / "docs" / "windows_exe.md").read_text(encoding="utf-8")
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        entry = REPO_ROOT / "build_tools" / ENTRY_SCRIPT

        self.assertTrue(entry.is_file())
        self.assertIn(ENTRY_SCRIPT, workflow)
        self.assertGreaterEqual(workflow.count(HELPER_NAME), 3)
        self.assertGreaterEqual(documentation.count(HELPER_NAME), 4)
        self.assertIn(f"{HELPER_NAME} =", pyproject)

    def test_release_upload_requires_explicit_dispatch_on_matching_tag(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "windows-exe.yml").read_text(encoding="utf-8")
        build_job, publish_job = workflow.split("\n  publish:\n", maxsplit=1)

        self.assertIn("contents: read", workflow)
        self.assertIn("type: boolean\n        default: false", workflow)
        self.assertIn("^[0-9A-Za-z][0-9A-Za-z._-]*$", build_job)
        self.assertNotIn("gh release", build_job)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.publish_release", publish_job)
        self.assertIn("contents: write", publish_job)
        self.assertIn('"$GITHUB_REF_TYPE" != "tag" || "$RELEASE_TAG" != "$GITHUB_REF_NAME"', publish_job)
        self.assertIn("actions/download-artifact@v4", publish_job)
        self.assertIn('release_notes="docs/releases/$RELEASE_TAG.md"', publish_job)
        self.assertIn('--notes-file "$release_notes"', publish_job)


if __name__ == "__main__":
    unittest.main()
