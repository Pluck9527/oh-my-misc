from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main


class StegoCliNamespaceTest(unittest.TestCase):
    def test_top_level_stego_stegpy_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            stego = root / "stego.png"
            output = root / "payload.txt"
            Image.new("RGBA", (48, 48), (40, 80, 120, 255)).save(cover)

            encode_exit = main(
                [
                    "stego",
                    "stegpy",
                    "hide",
                    str(cover),
                    "--text",
                    "flag{cross_carrier_namespace}",
                    "--output",
                    str(stego),
                    "--json",
                ]
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                decode_exit = main(
                    [
                        "stego",
                        "stegpy",
                        "extract",
                        str(stego),
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

            self.assertEqual(encode_exit, 0)
            self.assertEqual(decode_exit, 0)
            self.assertEqual(payload["operation"], "image.stegpy.extract")
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{cross_carrier_namespace}")

    def test_stego_help_keeps_only_cross_carrier_tools(self) -> None:
        parser = main.__globals__["build_parser"]()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as context:
            parser.parse_args(["stego", "--help"])
        help_text = stdout.getvalue()

        self.assertEqual(context.exception.code, 0)
        self.assertIn("stegpy", help_text)
        self.assertIn("steghide", help_text)
        self.assertNotIn("pixeljihad", help_text)
        self.assertNotIn("stegdetect", help_text)
        self.assertNotIn("jphs", help_text)
        self.assertNotIn("cloacked-pixel", help_text)


if __name__ == "__main__":
    unittest.main()
