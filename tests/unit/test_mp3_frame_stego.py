from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.mp3_frame_stego import extract_mp3_frame_field, scan_mp3_frame_fields


class MP3FrameFieldStegoTest(unittest.TestCase):
    def test_extract_copyright_bits_with_article_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.mp3"
            output = root / "payload.bin"
            sample.write_bytes(_article_style_mp3(b"flag{mp3}", field="copyright", base_size=1044))

            result = extract_mp3_frame_field(
                sample,
                output,
                field="copyright",
                start=0,
                end=None,
                base_frame_size=1044,
            )

            self.assertEqual(result.operation, "audio.mp3-field.extract")
            self.assertEqual(result.frame_count, 72)
            self.assertFalse(result.parsed_frames)
            self.assertEqual(output.read_bytes(), b"flag{mp3}")
            self.assertEqual(result.findings[0]["kind"], "flag")

    def test_extract_private_bits_with_parsed_frame_lengths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.mp3"
            output = root / "payload.bin"
            sample.write_bytes(_valid_mp3(b"PK\x03\x04", field="private"))

            result = extract_mp3_frame_field(sample, output, field="private")

            self.assertTrue(result.parsed_frames)
            self.assertEqual(result.frame_count, 32)
            self.assertEqual(output.read_bytes(), b"PK\x03\x04")
            self.assertEqual(result.findings[0]["kind"], "zip")

    def test_scan_writes_manifest_and_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.mp3"
            out = root / "candidates"
            sample.write_bytes(_valid_mp3(b"flag{scan}", field="original"))

            result = scan_mp3_frame_fields(
                sample,
                out,
                fields=["original", "copyright"],
                orders=["msb"],
            )

            self.assertEqual(result.operation, "audio.mp3-field.scan")
            self.assertTrue((out / "manifest.json").is_file())
            self.assertTrue((out / "original-msb.bin").is_file())
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["findings"][0]["kind"], "flag")
            self.assertEqual(manifest["findings"][0]["field"], "original")

    def test_cli_extract_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.mp3"
            output = root / "out.bin"
            sample.write_bytes(_valid_mp3(b"Hi", field="private"))

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "audio",
                        "mp3-field",
                        "extract",
                        str(sample),
                        "--field",
                        "private",
                        "-o",
                        str(output),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "audio.mp3-field.extract")
            self.assertEqual(output.read_bytes(), b"Hi")


def _bits(payload: bytes) -> list[int]:
    result: list[int] = []
    for byte in payload:
        for shift in range(7, -1, -1):
            result.append((byte >> shift) & 1)
    return result


def _article_style_mp3(payload: bytes, *, field: str, base_size: int) -> bytes:
    blob = bytearray()
    for bit in _bits(payload):
        header = bytearray(b"\xff\xfb\x90\x00")
        _set_field(header, field, bit)
        padding = (header[2] >> 1) & 1
        frame = header + b"\0" * (base_size + padding - 4)
        blob.extend(frame)
    return bytes(blob)


def _valid_mp3(payload: bytes, *, field: str) -> bytes:
    # MPEG-1 Layer III, 128 kbps, 44100 Hz: frame length 417 without padding.
    blob = bytearray()
    for bit in _bits(payload):
        header = bytearray(b"\xff\xfb\x90\x00")
        _set_field(header, field, bit)
        padding = (header[2] >> 1) & 1
        frame_length = (144 * 128000) // 44100 + padding
        blob.extend(header + b"\0" * (frame_length - 4))
    return bytes(blob)


def _set_field(header: bytearray, field: str, bit: int) -> None:
    if field == "copyright":
        header[3] = (header[3] & ~(1 << 3)) | (bit << 3)
    elif field == "original":
        header[3] = (header[3] & ~(1 << 2)) | (bit << 2)
    elif field == "private":
        header[2] = (header[2] & ~1) | bit
    elif field == "padding":
        header[2] = (header[2] & ~(1 << 1)) | (bit << 1)
    else:
        raise AssertionError(field)


if __name__ == "__main__":
    unittest.main()
