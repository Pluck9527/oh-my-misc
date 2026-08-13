from __future__ import annotations

import contextlib
import io
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from PIL import Image

from oh_my_misc.acropalypse import restore_acropalypse_png
from oh_my_misc.cli import main

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class AcropalypseTest(unittest.TestCase):
    def test_restore_synthetic_trailing_idat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable = root / "vulnerable.png"
            restored = root / "restored.png"
            scanlines = _rgba_scanlines(4, 4)
            _write_clean_png(vulnerable, 1, 1)
            _append_acropalypse_trailer(vulnerable, scanlines)

            result = restore_acropalypse_png(
                vulnerable,
                restored,
                width=4,
                height=4,
                mode="rgba",
            )

            self.assertEqual(result.operation, "image.acropalypse.restore")
            self.assertEqual(result.recovered_bytes, len(scanlines))
            with Image.open(restored) as image:
                self.assertEqual(image.mode, "RGBA")
                self.assertEqual(image.size, (4, 4))
                self.assertEqual(image.getpixel((0, 0)), (0, 0, 0, 255))
                self.assertEqual(image.getpixel((3, 3)), (120, 120, 120, 255))

    def test_cli_restore_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable = root / "vulnerable.png"
            restored = root / "restored.png"
            scanlines = _rgba_scanlines(4, 4)
            _write_clean_png(vulnerable, 1, 1)
            _append_acropalypse_trailer(vulnerable, scanlines)

            restore_stdout = io.StringIO()
            with contextlib.redirect_stdout(restore_stdout):
                restore_exit = main(
                    [
                        "image",
                        "acropalypse",
                        "restore",
                        str(vulnerable),
                        "--width",
                        "4",
                        "--height",
                        "4",
                        "--output",
                        str(restored),
                        "--json",
                    ]
                )
            restore_payload = json.loads(restore_stdout.getvalue())

            self.assertEqual(restore_exit, 0)
            self.assertEqual(restore_payload["operation"], "image.acropalypse.restore")
            self.assertEqual(restore_payload["recovered_bytes"], len(scanlines))


def _rgba_scanlines(width: int, height: int) -> bytes:
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            value = (x + y) * 20
            rows.extend((value, value, value, 255))
    return bytes(rows)


def _write_clean_png(path: Path, width: int, height: int) -> None:
    row = b"\x00" + b"\x00\x00\x00\xff" * width
    with path.open("wb") as stream:
        stream.write(PNG_SIGNATURE)
        _write_chunk(stream, b"IHDR", struct.pack(">II5B", width, height, 8, 6, 0, 0, 0))
        _write_chunk(stream, b"IDAT", zlib.compress(row * height))
        _write_chunk(stream, b"IEND", b"")


def _append_acropalypse_trailer(path: Path, recovered_scanlines: bytes) -> None:
    compressor = zlib.compressobj(level=6, wbits=-15)
    raw_deflate = compressor.compress(recovered_scanlines) + compressor.flush()
    trailer = b"\x00" * 8 + _png_chunk(b"IDAT", raw_deflate + b"\x00" * 4) + _png_chunk(b"IEND", b"")
    with path.open("ab") as stream:
        stream.write(trailer)


def _png_chunk(chunk_type: bytes, body: bytes) -> bytes:
    return (
        struct.pack(">I", len(body))
        + chunk_type
        + body
        + struct.pack(">I", zlib.crc32(chunk_type + body) & 0xFFFFFFFF)
    )


def _write_chunk(stream: io.BufferedWriter, chunk_type: bytes, body: bytes) -> None:
    stream.write(_png_chunk(chunk_type, body))


if __name__ == "__main__":
    unittest.main()
