from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.stegdetect import run_stegdetect


class StegdetectTest(unittest.TestCase):
    def test_outguess_comment_signature_scores_positive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "suspect.jpg"
            _write_jpeg_with_comment(image, b"OutGuess 0.13 hidden data")

            result = run_stegdetect([image], types="o", sensitivity=10.0)

            self.assertEqual(result.operation, "image.stegdetect")
            self.assertEqual(result.positive_count, 1)
            self.assertEqual(result.findings[0]["kind"], "outguess")
            self.assertEqual(result.findings[0]["stars"], "***")

    def test_clean_jpeg_reports_negative_for_jopi(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "clean.jpg"
            Image.new("RGB", (16, 16), "white").save(image, "JPEG")

            result = run_stegdetect([image], types="jopi", sensitivity=10.0)

            self.assertEqual(result.count, 4)
            self.assertEqual(result.positive_count, 0)
            self.assertTrue(all(not finding["positive"] for finding in result.findings))

    def test_cli_json_uses_stegdetect_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "jphide.jpg"
            report = root / "report.txt"
            _write_jpeg_with_comment(image, b"JPHide and Seek marker")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "stegdetect",
                        str(image),
                        "-t",
                        "jopi",
                        "-s",
                        "10.0",
                        "--output",
                        str(report),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.stegdetect")
            self.assertGreaterEqual(payload["positive_count"], 1)
            self.assertIn("jphide***", report.read_text(encoding="utf-8"))

    def test_original_f5_comment_marker_scores_positive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "f5.jpg"
            _write_jpeg_with_comment(
                image,
                b"JPEG Encoder Copyright 1998, James R. Weeks and BioElectroMech.",
            )

            result = run_stegdetect([image], types="fF", sensitivity=10.0)

            self.assertEqual(result.positive_count, 2)
            self.assertEqual([finding["kind"] for finding in result.findings], ["f5", "f5-slow"])
            self.assertTrue(all(finding["stars"] == "***" for finding in result.findings))

    def test_append_selector_detects_data_after_eoi(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "append.jpg"
            Image.new("RGB", (16, 16), (1, 2, 3)).save(image, "JPEG")
            with image.open("ab") as stream:
                stream.write(b"hidden trailer payload")

            result = run_stegdetect([image], types="a", sensitivity=10.0)

            self.assertEqual(result.positive_count, 1)
            self.assertEqual(result.findings[0]["kind"], "appended")
            self.assertIn("data after EOI", result.findings[0]["evidence"][0])

    def test_invisible_secrets_comment_length_pattern_scores_positive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "invisible.jpg"
            _write_jpeg_with_comments(image, [b"cover", (4).to_bytes(4, "little") + b"data"])

            result = run_stegdetect([image], types="i", sensitivity=10.0)

            self.assertEqual(result.positive_count, 1)
            self.assertEqual(result.findings[0]["kind"], "invisible-secrets")


def _write_jpeg_with_comment(path: Path, comment: bytes) -> None:
    Image.new("RGB", (16, 16), (120, 80, 40)).save(path, "JPEG")
    data = path.read_bytes()
    com = b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment
    path.write_bytes(data[:2] + com + data[2:])


def _write_jpeg_with_comments(path: Path, comments: list[bytes]) -> None:
    Image.new("RGB", (16, 16), (120, 80, 40)).save(path, "JPEG")
    data = path.read_bytes()
    chunks = b"".join(b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment for comment in comments)
    path.write_bytes(data[:2] + chunks + data[2:])


if __name__ == "__main__":
    unittest.main()
