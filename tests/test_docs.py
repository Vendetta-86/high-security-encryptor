from pathlib import Path
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
README_PATH = PROJECT_ROOT / "README.md"


class DocumentationTests(unittest.TestCase):
    def test_readme_links_to_existing_docs(self) -> None:
        """README links to local docs should not go stale."""

        readme_text = README_PATH.read_text(encoding="utf-8")
        local_doc_links = re.findall(r"\]\((docs/[^)]+)\)", readme_text)

        self.assertIn("docs/security_model.md", local_doc_links)
        self.assertIn("docs/operations.md", local_doc_links)
        for link in local_doc_links:
            self.assertTrue((PROJECT_ROOT / link).is_file(), link)


if __name__ == "__main__":
    unittest.main()
