from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.cloacked_pixel import (
    analyse_cloacked_pixel,
    brute_cloacked_pixel,
    extract_cloacked_pixel,
    hide_cloacked_pixel,
)


class CloackedPixelTest(unittest.TestCase):
    def test_hide_extract_roundtrip_with_deterministic_iv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            payload = root / "secret.bin"
            stego = root / "stego.png"
            extracted = root / "extracted.bin"
            Image.new("RGB", (32, 32), (100, 120, 140)).save(source)
            payload.write_bytes(b"flag{cloacked_pixel}\x00data")

            hide_result = hide_cloacked_pixel(
                source,
                payload,
                stego,
                password="p@ssw0rd",
                iv=b"\x01" * 16,
            )
            extract_result = extract_cloacked_pixel(stego, extracted, password="p@ssw0rd")

            self.assertEqual(hide_result.operation, "image.cloacked-pixel.hide")
            self.assertEqual(extract_result.operation, "image.cloacked-pixel.extract")
            self.assertEqual(extracted.read_bytes(), payload.read_bytes())
            self.assertGreater(hide_result.encrypted_bytes, hide_result.payload_bytes)

    def test_cli_json_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            payload = root / "secret.txt"
            stego = root / "stego.png"
            extracted = root / "secret-out.txt"
            Image.new("RGB", (32, 32), "white").save(source)
            payload.write_text("hello cloacked", encoding="utf-8")

            hide_stdout = io.StringIO()
            with contextlib.redirect_stdout(hide_stdout):
                hide_exit = main(
                    [
                        "image",
                        "cloacked-pixel",
                        "hide",
                        str(source),
                        "--payload",
                        str(payload),
                        "--password",
                        "pw",
                        "--output",
                        str(stego),
                        "--json",
                    ]
                )
            extract_stdout = io.StringIO()
            with contextlib.redirect_stdout(extract_stdout):
                extract_exit = main(
                    [
                        "image",
                        "cloacked-pixel",
                        "extract",
                        str(stego),
                        "--password",
                        "pw",
                        "--output",
                        str(extracted),
                        "--json",
                    ]
                )

            hide_payload = json.loads(hide_stdout.getvalue())
            extract_payload = json.loads(extract_stdout.getvalue())
            self.assertEqual(hide_exit, 0)
            self.assertEqual(extract_exit, 0)
            self.assertEqual(hide_payload["operation"], "image.cloacked-pixel.hide")
            self.assertEqual(extract_payload["operation"], "image.cloacked-pixel.extract")
            self.assertEqual(extracted.read_text(encoding="utf-8"), "hello cloacked")

    def test_brute_wordlist_finds_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            payload = root / "secret.txt"
            stego = root / "stego.png"
            wordlist = root / "words.txt"
            output = root / "bruted.txt"
            Image.new("RGB", (32, 32), (10, 20, 30)).save(source)
            payload.write_text("flag{bruted}", encoding="utf-8")
            wordlist.write_text("123456\nletmein\ncorrect horse\n", encoding="utf-8")
            hide_cloacked_pixel(source, payload, stego, password="letmein", iv=b"\x03" * 16)

            result = brute_cloacked_pixel(
                stego,
                wordlist,
                output,
                contains=b"flag{",
            )

            self.assertEqual(result.operation, "image.cloacked-pixel.brute")
            self.assertEqual(result.found_password, "letmein")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{bruted}")

    def test_brute_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            payload = root / "secret.txt"
            stego = root / "stego.png"
            wordlist = root / "words.txt"
            output = root / "bruted.txt"
            Image.new("RGB", (32, 32), (10, 20, 30)).save(source)
            payload.write_text("PK demo payload", encoding="utf-8")
            wordlist.write_text("bad\nhunter2\n", encoding="utf-8")
            hide_cloacked_pixel(source, payload, stego, password="hunter2", iv=b"\x04" * 16)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "cloacked-pixel",
                        "brute",
                        str(stego),
                        "--wordlist",
                        str(wordlist),
                        "--prefix",
                        "PK",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload_json = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload_json["operation"], "image.cloacked-pixel.brute")
            self.assertEqual(payload_json["found_password"], "hunter2")
            self.assertEqual(payload_json["attempts"], 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "PK demo payload")

    def test_extract_cli_accepts_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            payload = root / "secret.txt"
            stego = root / "stego.png"
            wordlist = root / "words.txt"
            output = root / "extracted.txt"
            Image.new("RGB", (32, 32), (10, 20, 30)).save(source)
            payload.write_text("flag{extract_wordlist}", encoding="utf-8")
            wordlist.write_text("bad\ns3cr3t\n", encoding="utf-8")
            hide_cloacked_pixel(source, payload, stego, password="s3cr3t", iv=b"\x05" * 16)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "cloacked-pixel",
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
            payload_json = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload_json["operation"], "image.cloacked-pixel.brute")
            self.assertEqual(payload_json["found_password"], "s3cr3t")
            self.assertEqual(payload_json["attempts"], 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{extract_wordlist}")

    def test_analyse_reports_channel_means(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            payload = root / "secret.bin"
            stego = root / "stego.png"
            Image.new("RGB", (32, 32), (80, 82, 84)).save(source)
            payload.write_bytes(bytes(range(64)))
            hide_cloacked_pixel(source, payload, stego, password="pw", iv=b"\x02" * 16)

            result = analyse_cloacked_pixel(stego, block_size=64)

            self.assertEqual(result.operation, "image.cloacked-pixel.analyse")
            self.assertEqual(set(result.channel_means or {}), {"r", "g", "b"})
            self.assertGreater(result.capacity_bytes, 0)
            self.assertGreaterEqual(result.count, 0)


if __name__ == "__main__":
    unittest.main()
