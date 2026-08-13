from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.f5 import _F5Random, extract_f5, hide_f5


class F5NativeTest(unittest.TestCase):
    def test_sha1prng_matches_f5_java_sequence(self) -> None:
        random = _F5Random(b"secret")
        values = [random.get_next_byte() for _ in range(24)]

        self.assertEqual(
            values,
            [
                20,
                -26,
                85,
                103,
                -85,
                -37,
                81,
                53,
                -48,
                -49,
                -39,
                -89,
                11,
                48,
                50,
                -63,
                121,
                -92,
                -98,
                -25,
                103,
                -12,
                18,
                102,
            ],
        )

    def test_f5_python_hide_extract_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            payload = root / "payload.txt"
            stego = root / "stego.jpg"
            output = root / "out.txt"
            _write_noisy_jpeg(cover)
            payload.write_bytes(b"flag{f5_native_roundtrip}")

            hide_result = hide_f5(cover, stego, payload, password="secret")
            extract_result = extract_f5(stego, output, password="secret")

            self.assertEqual(hide_result.operation, "image.f5.hide")
            self.assertEqual(extract_result.operation, "image.f5.extract")
            self.assertEqual(output.read_bytes(), b"flag{f5_native_roundtrip}")

    def test_f5_cli_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            payload = root / "payload.txt"
            stego = root / "stego.jpg"
            output = root / "out.txt"
            wordlist = root / "words.txt"
            _write_noisy_jpeg(cover)
            payload.write_bytes(b"flag{f5_wordlist}")
            wordlist.write_text("bad\nsecret\n", encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "image",
                        "f5",
                        "hide",
                        str(cover),
                        "--payload",
                        str(payload),
                        "-p",
                        "secret",
                        "-o",
                        str(stego),
                    ]
                ),
                0,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "f5",
                        "extract",
                        str(stego),
                        "--wordlist",
                        str(wordlist),
                        "--no-default",
                        "--contains",
                        "flag{",
                        "-o",
                        str(output),
                        "--json",
                    ]
                )
            result = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(result["operation"], "image.f5.brute")
            self.assertEqual(result["found_password"], "secret")
            self.assertEqual(result["attempts"], 2)
            self.assertEqual(output.read_bytes(), b"flag{f5_wordlist}")


def _write_noisy_jpeg(path: Path) -> None:
    image = Image.new("RGB", (128, 128))
    image.putdata(
        [
            ((x * 37 + y * 17) % 256, (x * 11 + y * 53) % 256, (x * 73 + y * 29) % 256)
            for y in range(128)
            for x in range(128)
        ]
    )
    image.save(path, "JPEG", quality=90)


if __name__ == "__main__":
    unittest.main()
