from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.backpaper import (
    crc16,
    decode_backpaper,
    decode_paperback_block,
    encode_backpaper,
    encode_paperback_block,
)
from oh_my_misc.cli import main


class BackpaperTest(unittest.TestCase):
    def test_crc_known_vector(self) -> None:
        self.assertEqual(crc16(b"123456789"), 0x31C3)

    def test_block_rs_corrects_sixteen_bytes(self) -> None:
        expected = encode_paperback_block(0x123456, bytes(range(90)))
        damaged = bytearray(expected)
        for index in range(16):
            damaged[index * 7] ^= index + 1
        restored, corrected = decode_paperback_block(damaged)
        self.assertEqual(restored, expected)
        self.assertEqual(corrected, 16)

    def test_plain_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "flag.txt"
            page = root / "paper.png"
            output = root / "restored.txt"
            payload = (b"flag{paperback-native-port}\n" * 31) + bytes(range(64))
            source.write_bytes(payload)

            encoded = encode_backpaper(source, page)
            decoded = decode_backpaper([page], output)

            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(encoded.operation, "image.backpaper.encode")
            self.assertEqual(decoded.operation, "image.backpaper.decode")
            self.assertTrue(decoded.crc_valid)
            self.assertGreater(decoded.blocks, 0)

    def test_encrypted_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "secret.bin"
            page = root / "paper.png"
            output = root / "restored.bin"
            payload = bytes(range(256)) * 4
            source.write_bytes(payload)

            encode_backpaper(source, page, password="http://www.verymuch.net")
            result = decode_backpaper(
                [page], output, password="http://www.verymuch.net"
            )

            self.assertEqual(output.read_bytes(), payload)
            self.assertTrue(result.encrypted)

    def test_high_contrast_scaled_scan_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "scan.dat"
            page = root / "paper.png"
            scan = root / "scan.png"
            output = root / "restored.dat"
            payload = b"PaperBack scan fixture" * 18
            source.write_bytes(payload)
            encode_backpaper(source, page, compress=False)
            with Image.open(page) as image:
                image.resize(
                    (round(image.width * 1.35), round(image.height * 1.35)),
                    Image.Resampling.BILINEAR,
                ).save(scan)

            decode_backpaper([scan], output)
            self.assertEqual(output.read_bytes(), payload)

    def test_xor_recovery_restores_one_unreadable_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "recovery.dat"
            page = root / "paper.png"
            damaged_page = root / "damaged.png"
            output = root / "restored.dat"
            payload = bytes(range(256)) * 3
            source.write_bytes(payload)
            encode_backpaper(source, page, compress=False)

            with Image.open(page) as source_image:
                image = source_image.convert("L")
            # Cell 1 is the first data block for the default 5-way group.
            x_origin = 25 + 105 + 6
            y_origin = 25 + 6
            for byte_index in range(17):
                row = byte_index // 4
                column = (byte_index % 4) * 8
                x = x_origin + column * 3
                y = y_origin + row * 3
                replacement = 255 if image.getpixel((x, y)) < 128 else 64
                for y_offset in range(2):
                    for x_offset in range(2):
                        image.putpixel((x + x_offset, y + y_offset), replacement)
            image.save(damaged_page)

            result = decode_backpaper([damaged_page], output)
            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(result.recovered_blocks, 1)

    def test_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "flag.txt"
            page = root / "paper.png"
            source.write_text("flag{paperbak-cli}", encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "paperbak",
                        "encode",
                        str(source),
                        "--output",
                        str(page),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.backpaper.encode")
            self.assertTrue(page.is_file())


if __name__ == "__main__":
    unittest.main()
