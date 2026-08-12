from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.inspection import inspect_file

CORPUS = Path(__file__).parents[1] / "corpus"


class InspectionTest(unittest.TestCase):
    def test_png_profile(self) -> None:
        result = inspect_file(CORPUS / "sample.png")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.summary["kind"], "png")
        self.assertEqual((result.summary["width"], result.summary["height"]), (1, 1))
        self.assertEqual(len(result.summary["sha256"]), 64)

    def test_extension_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            disguised = Path(directory) / "sample.txt"
            disguised.write_bytes((CORPUS / "sample.png").read_bytes())
            result = inspect_file(disguised)
        self.assertIn("extension_mismatch", [finding.code for finding in result.findings])

    def test_json_cli(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["inspect", str(CORPUS / "sample.png"), "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["operation"], "inspect")
        self.assertEqual(payload["summary"]["kind"], "png")

    def test_missing_file_has_machine_readable_failure(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["inspect", "/definitely/missing/oh-my-misc", "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["errors"][0]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
