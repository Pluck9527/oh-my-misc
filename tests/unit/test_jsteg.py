from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image, ImageDraw

from oh_my_misc.cli import main
from oh_my_misc.jsteg import hide_jsteg, reveal_jsteg


class JstegTest(unittest.TestCase):
    def test_native_jpeg_roundtrip_with_cli_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            stego = root / "stego.jpg"
            output = root / "flag.txt"
            _write_jpeg(cover)

            hide_result = hide_jsteg(cover, stego, text="flag{native_jsteg}")
            reveal_result = reveal_jsteg(stego, output)

            self.assertEqual(hide_result.operation, "image.jsteg.hide")
            self.assertEqual(reveal_result.operation, "image.jsteg.reveal")
            self.assertGreaterEqual(hide_result.capacity_bytes, 9 + len("flag{native_jsteg}"))
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{native_jsteg}")
            self.assertTrue(stego.read_bytes().startswith(b"\xff\xd8"))

    def test_raw_mode_roundtrip_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            payload = root / "payload.bin"
            stego = root / "stego.jpg"
            output = root / "raw.bin"
            _write_jpeg(cover)
            payload.write_bytes(b"\x00RAW-JSTEG")

            hide_jsteg(cover, stego, payload_path=payload, raw=True)
            result = reveal_jsteg(stego, output, raw=True)

            self.assertTrue(result.raw)
            self.assertEqual(output.read_bytes()[: payload.stat().st_size], payload.read_bytes())

    def test_reveal_without_magic_fails_unless_raw(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            payload = root / "payload.bin"
            stego = root / "stego.jpg"
            output = root / "out.bin"
            _write_jpeg(cover)
            payload.write_bytes(b"plain")
            hide_jsteg(cover, stego, payload_path=payload, raw=True)

            with self.assertRaisesRegex(ValueError, "jsteg CLI magic"):
                reveal_jsteg(stego, output)

    def test_cli_hide_and_reveal_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            stego = root / "stego.jpg"
            output = root / "flag.txt"
            _write_jpeg(cover)

            hide_stdout = io.StringIO()
            with contextlib.redirect_stdout(hide_stdout):
                hide_code = main(
                    [
                        "image",
                        "jsteg",
                        "hide",
                        str(cover),
                        "--text",
                        "flag{cli_jsteg}",
                        "-o",
                        str(stego),
                        "--json",
                    ]
                )
            reveal_stdout = io.StringIO()
            with contextlib.redirect_stdout(reveal_stdout):
                reveal_code = main(
                    [
                        "image",
                        "jsteg",
                        "reveal",
                        str(stego),
                        "-o",
                        str(output),
                        "--json",
                    ]
                )

            hide_payload = json.loads(hide_stdout.getvalue())
            reveal_payload = json.loads(reveal_stdout.getvalue())
            self.assertEqual(hide_code, 0)
            self.assertEqual(reveal_code, 0)
            self.assertEqual(hide_payload["operation"], "image.jsteg.hide")
            self.assertEqual(reveal_payload["operation"], "image.jsteg.reveal")
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{cli_jsteg}")


def _write_jpeg(path: Path) -> None:
    image = Image.new("RGB", (320, 320), "white")
    draw = ImageDraw.Draw(image)
    for y in range(320):
        for x in range(320):
            if (x * 17 + y * 31) % 29 < 14:
                image.putpixel((x, y), ((x * 5 + y) % 256, (x + y * 7) % 256, (x * 11) % 256))
    for offset in range(-320, 320, 7):
        draw.line((offset, 0, offset + 320, 320), fill=(offset % 255, 80, 180), width=2)
    image.save(path, "JPEG", quality=95)


if __name__ == "__main__":
    unittest.main()
