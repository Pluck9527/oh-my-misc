from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.wbstego import (
    analyse_wbstego_bmp,
    brute_wbstego,
    extract_wbstego,
    extract_wbstego_bmp,
    hide_wbstego,
    hide_wbstego_bmp,
)


class WbStegoNativeTest(unittest.TestCase):
    def test_wbstego_24bit_bmp_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.bmp"
            payload = root / "flag.txt"
            stego = root / "stego.bmp"
            output = root / "out.bin"
            _write_bmp(cover)
            payload.write_bytes(b"flag{wbstego_native}")

            hide_result = hide_wbstego_bmp(cover, stego, payload)
            extract_result = extract_wbstego_bmp(stego, output)

            self.assertEqual(hide_result.operation, "image.wbstego.hide")
            self.assertEqual(extract_result.operation, "image.wbstego.extract")
            self.assertEqual(extract_result.embedded_extension, "txt")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_native}")

    def test_wbstego_distributed_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.bmp"
            payload = root / "flag.bin"
            stego = root / "stego.bmp"
            output = root / "out.bin"
            _write_bmp(cover, size=(96, 96))
            payload.write_bytes(b"flag{distributed}")

            hide_wbstego_bmp(cover, stego, payload, distribute=True)
            result = extract_wbstego_bmp(stego, output)

            self.assertTrue(result.distributed)
            self.assertEqual(result.embedded_extension, "bin")
            self.assertEqual(output.read_bytes(), b"flag{distributed}")

    def test_wbstego_cli_json_and_analyse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.bmp"
            payload = root / "payload.dat"
            stego = root / "stego.bmp"
            output = root / "payload.out"
            _write_bmp(cover)
            payload.write_bytes(b"flag{cli_wbstego}")

            self.assertGreater(analyse_wbstego_bmp(cover).capacity_bytes, len(payload.read_bytes()))
            self.assertEqual(
                main(
                    [
                        "image",
                        "wbstego",
                        "hide",
                        str(cover),
                        "--payload",
                        str(payload),
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
                        "wbstego",
                        "extract",
                        str(stego),
                        "-o",
                        str(output),
                        "--json",
                    ]
                )
            data = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(data["operation"], "image.wbstego.extract")
            self.assertEqual(data["embedded_extension"], "dat")
            self.assertEqual(output.read_bytes(), b"flag{cli_wbstego}")

    def test_wbstego_rle8_bmp_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover-rle8.bmp"
            payload = root / "flag.txt"
            stego = root / "stego-rle8.bmp"
            output = root / "out.bin"
            _write_rle_bmp(cover, bit_count=8, carrier_bytes=260)
            payload.write_bytes(b"flag{wbstego_rle8}")

            hide_result = hide_wbstego_bmp(cover, stego, payload)
            extract_result = extract_wbstego_bmp(stego, output)

            self.assertEqual(hide_result.compression, 1)
            self.assertEqual(extract_result.embedded_extension, "txt")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_rle8}")

    def test_wbstego_rle4_bmp_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover-rle4.bmp"
            payload = root / "flag.txt"
            stego = root / "stego-rle4.bmp"
            output = root / "out.bin"
            _write_rle_bmp(cover, bit_count=4, carrier_bytes=140)
            payload.write_bytes(b"flag{wbstego_rle4}")

            hide_result = hide_wbstego_bmp(cover, stego, payload)
            extract_result = extract_wbstego_bmp(stego, output)

            self.assertEqual(hide_result.compression, 2)
            self.assertEqual(extract_result.embedded_extension, "txt")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_rle4}")

    def test_wbstego_ascii_replace_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.asc"
            payload = root / "flag.dat"
            stego = root / "stego.asc"
            output = root / "out.bin"
            cover.write_bytes((b"A " * 300) + (b"\x00Z" * 80))
            payload.write_bytes(b"flag{wbstego_asc}")

            hide_result = hide_wbstego(cover, stego, payload, carrier="asc")
            extract_result = extract_wbstego(stego, output, carrier="asc")

            self.assertEqual(hide_result.carrier_format, "ASC")
            self.assertEqual(extract_result.embedded_extension, "dat")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_asc}")

    def test_wbstego_txt_insert_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.txt"
            payload = root / "flag.txt"
            stego = root / "stego.txt"
            output = root / "out.bin"
            cover.write_bytes(b"".join(f"line {i:03d}\r\n".encode() for i in range(120)))
            payload.write_bytes(b"flag{wbstego_txt}")

            hide_result = hide_wbstego(cover, stego, payload, carrier="txt")
            extract_result = extract_wbstego(stego, output, carrier="txt")

            self.assertEqual(hide_result.carrier_format, "TXT")
            self.assertEqual(extract_result.embedded_extension, "txt")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_txt}")

    def test_wbstego_html_insert_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.html"
            payload = root / "flag.html"
            stego = root / "stego.html"
            output = root / "out.bin"
            cover.write_bytes(
                b"<html>\r\n<body>\r\n"
                + b"".join(f"<p>{i:03d}</p>\r\n".encode() for i in range(120))
                + b"</body>\r\n</html>\r\n"
            )
            payload.write_bytes(b"flag{wbstego_html}")

            hide_result = hide_wbstego(cover, stego, payload, carrier="html")
            extract_result = extract_wbstego(stego, output, carrier="html")

            self.assertEqual(hide_result.carrier_format, "HTML")
            self.assertEqual(extract_result.embedded_extension, "htm")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_html}")

    def test_wbstego_pdf_insert_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.pdf"
            payload = root / "flag.pdf"
            stego = root / "stego.pdf"
            output = root / "out.bin"
            cover.write_bytes(_pdf_like_cover(120))
            payload.write_bytes(b"flag{wbstego_pdf}")

            hide_result = hide_wbstego(cover, stego, payload, carrier="pdf")
            extract_result = extract_wbstego(stego, output, carrier="pdf")

            self.assertEqual(hide_result.carrier_format, "PDF")
            self.assertEqual(extract_result.embedded_extension, "pdf")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_pdf}")

    def test_wbstego_cli_text_carrier_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.txt"
            payload = root / "payload.bin"
            stego = root / "stego.txt"
            output = root / "payload.out"
            cover.write_bytes(b"".join(f"row {i:03d}\n".encode() for i in range(120)))
            payload.write_bytes(b"flag{cli_wbstego_txt}")

            self.assertEqual(
                main(
                    [
                        "image",
                        "wbstego",
                        "hide",
                        str(cover),
                        "--carrier",
                        "txt",
                        "--payload",
                        str(payload),
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
                        "wbstego",
                        "extract",
                        str(stego),
                        "--carrier",
                        "txt",
                        "-o",
                        str(output),
                        "--json",
                    ]
                )
            data = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(data["carrier_format"], "TXT")
            self.assertEqual(data["embedded_extension"], "bin")
            self.assertEqual(output.read_bytes(), b"flag{cli_wbstego_txt}")

    def test_wbstego_password_crypt_mix_transmit_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.txt"
            payload = root / "flag.txt"
            stego = root / "stego.txt"
            output = root / "out.bin"
            cover.write_bytes(b"".join(f"secret row {i:03d}\r\n".encode() for i in range(180)))
            payload.write_bytes(b"flag{wbstego_password}")

            hide_result = hide_wbstego(
                cover,
                stego,
                payload,
                carrier="txt",
                password="ABCDEF",
                crypt=True,
                mix=True,
                transmit_password=True,
            )
            extract_result = extract_wbstego(stego, output, carrier="txt", password="ABCDEF")

            self.assertTrue(hide_result.password_protected)
            self.assertTrue(extract_result.password_protected)
            self.assertTrue(extract_result.password_verified)
            self.assertEqual(extract_result.embedded_extension, "txt")
            self.assertEqual(output.read_bytes(), b"flag{wbstego_password}")

    def test_wbstego_wordlist_bruteforce(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.asc"
            payload = root / "flag.bin"
            stego = root / "stego.asc"
            output = root / "out.bin"
            wordlist = root / "passwords.txt"
            cover.write_bytes((b"A " * 1000) + (b"\x00Z" * 200))
            payload.write_bytes(b"flag{wbstego_brute}")
            wordlist.write_text("guess\nabc123\n", encoding="utf-8")

            hide_wbstego(
                cover,
                stego,
                payload,
                carrier="asc",
                password="abc123",
            )
            result = brute_wbstego(
                stego,
                wordlist,
                output,
                carrier="asc",
                contains=b"flag{",
                include_default=False,
            )

            self.assertEqual(result.found_password, "abc123")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(output.read_bytes(), b"flag{wbstego_brute}")

    def test_wbstego_top_level_stego_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.txt"
            payload = root / "payload.txt"
            stego = root / "stego.txt"
            output = root / "out.bin"
            cover.write_bytes(b"".join(f"stego row {i:03d}\r\n".encode() for i in range(120)))
            payload.write_bytes(b"flag{stego_namespace}")

            self.assertEqual(
                main(
                    [
                        "stego",
                        "wbstego",
                        "hide",
                        str(cover),
                        "--carrier",
                        "txt",
                        "--payload",
                        str(payload),
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
                        "stego",
                        "wbstego",
                        "extract",
                        str(stego),
                        "--carrier",
                        "txt",
                        "-o",
                        str(output),
                        "--json",
                    ]
                )
            data = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(data["operation"], "image.wbstego.extract")
            self.assertEqual(data["carrier_format"], "TXT")
            self.assertEqual(output.read_bytes(), b"flag{stego_namespace}")


def _write_bmp(path: Path, *, size: tuple[int, int] = (64, 64)) -> None:
    width, height = size
    image = Image.new("RGB", size)
    image.putdata(
        [
            ((x * 13 + y * 7) % 256, (x * 5 + y * 17) % 256, (x * 29 + y * 3) % 256)
            for y in range(height)
            for x in range(width)
        ]
    )
    image.save(path, "BMP")


def _write_rle_bmp(path: Path, *, bit_count: int, carrier_bytes: int) -> None:
    compression = 1 if bit_count == 8 else 2
    palette_entries = 256 if bit_count == 8 else 16
    palette = bytearray()
    for index in range(palette_entries):
        palette.extend((index, index, index, 0))
    pixel_data = bytearray()
    for index in range(carrier_bytes):
        pixel_data.extend((1, (index * 7) & 0xFE))
    pixel_data.extend((0, 1))
    offset = 14 + 40 + len(palette)
    file_size = offset + len(pixel_data)
    header = bytearray(b"BM")
    header.extend(file_size.to_bytes(4, "little"))
    header.extend((0).to_bytes(4, "little"))
    header.extend(offset.to_bytes(4, "little"))
    dib = bytearray()
    dib.extend((40).to_bytes(4, "little"))
    dib.extend(max(1, carrier_bytes).to_bytes(4, "little"))
    dib.extend((1).to_bytes(4, "little"))
    dib.extend((1).to_bytes(2, "little"))
    dib.extend(bit_count.to_bytes(2, "little"))
    dib.extend(compression.to_bytes(4, "little"))
    dib.extend(len(pixel_data).to_bytes(4, "little"))
    dib.extend((2835).to_bytes(4, "little"))
    dib.extend((2835).to_bytes(4, "little"))
    dib.extend(palette_entries.to_bytes(4, "little"))
    dib.extend((0).to_bytes(4, "little"))
    path.write_bytes(bytes(header + dib + palette + pixel_data))


def _pdf_like_cover(lines: int) -> bytes:
    outside = b"".join(f"% carrier line {i:03d}\r".encode() for i in range(lines))
    inside_object = b"1 0 obj\r<< /Type /Catalog >>\rendobj\r"
    trailer = b"trailer\r<< /Root 1 0 R >>\r%%EOF\r"
    return b"%PDF-1.4\r" + outside[: len(outside) // 2] + inside_object + outside[len(outside) // 2 :] + trailer


if __name__ == "__main__":
    unittest.main()
