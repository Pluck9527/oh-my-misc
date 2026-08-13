from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.stegpy_compat import brute_stegpy, extract_stegpy, hide_stegpy


class StegpyCompatTest(unittest.TestCase):
    def test_hide_extract_text_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            stego = root / "stego.png"
            output = root / "payload.txt"
            Image.new("RGB", (32, 32), (100, 120, 140)).save(cover)

            hide_result = hide_stegpy(cover, stego, text="flag{stegpy_text}")
            extract_result = extract_stegpy(stego, output)

            self.assertEqual(hide_result.operation, "image.stegpy.hide")
            self.assertEqual(extract_result.operation, "image.stegpy.extract")
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{stegpy_text}")
            self.assertEqual(extract_result.bits, 2)

    def test_hide_extract_file_with_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            secret = root / "secret.bin"
            stego = root / "stego.png"
            output = root / "secret.out"
            Image.new("RGB", (48, 48), "white").save(cover)
            secret.write_bytes(b"\x00flag{stegpy_file}\xff")

            hide_result = hide_stegpy(
                cover,
                stego,
                payload_path=secret,
                password="hunter2",
                bits=4,
            )
            extract_result = extract_stegpy(stego, output, password="hunter2")

            self.assertTrue(hide_result.encrypted)
            self.assertEqual(extract_result.payload_filename, "secret.bin")
            self.assertEqual(extract_result.bits, 4)
            self.assertEqual(output.read_bytes(), secret.read_bytes())

    def test_extract_cli_accepts_custom_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            stego = root / "stego.png"
            wordlist = root / "words.txt"
            output = root / "out.txt"
            Image.new("RGB", (48, 48), (10, 20, 30)).save(cover)
            wordlist.write_text("bad\ns3cr3t\n", encoding="utf-8")
            hide_stegpy(cover, stego, text="flag{stegpy_wordlist}", password="s3cr3t")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "stegpy",
                        "extract",
                        str(stego),
                        "--wordlist",
                        str(wordlist),
                        "--contains",
                        "flag{",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.stegpy.brute")
            self.assertEqual(payload["found_password"], "s3cr3t")
            self.assertEqual(payload["attempts"], 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{stegpy_wordlist}")

    def test_brute_stegpy_prefix_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            stego = root / "stego.png"
            wordlist = root / "words.txt"
            output = root / "out.bin"
            Image.new("RGB", (48, 48), (1, 2, 3)).save(cover)
            wordlist.write_text("guess\nletmein\n", encoding="utf-8")
            hide_stegpy(cover, stego, text="PK stegpy zip", password="letmein")

            result = brute_stegpy(stego, wordlist, output, prefix=b"PK")

            self.assertEqual(result.found_password, "letmein")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "PK stegpy zip")


if __name__ == "__main__":
    unittest.main()
