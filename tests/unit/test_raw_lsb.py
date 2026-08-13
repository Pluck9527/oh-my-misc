from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

import numpy as np

from oh_my_misc.cli import main
from oh_my_misc.raw_lsb import extract_raw_lsb, scan_raw_lsb


class RawLsbTest(unittest.TestCase):
    def test_extract_visible_raw_lsb_msb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_file = root / "sample.ARW"
            output = root / "payload.bin"
            raw_file.write_bytes(b"fake raw")
            payload = b"PK\x03\x04demo"
            _install_fake_rawpy(self, _plane_for(payload, order="msb"))

            result = extract_raw_lsb(raw_file, output, bit=0, order="msb")

            self.assertEqual(result.operation, "image.raw-lsb.extract")
            self.assertEqual(result.width, 8)
            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(result.findings[0]["kind"], "zip")

    def test_extract_lsb_order_and_crop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_file = root / "sample.dng"
            output = root / "payload.bin"
            raw_file.write_bytes(b"fake raw")
            payload = b"AB"
            plane = np.zeros((4, 16), dtype=np.uint16)
            plane[1:3, 4:12] = _plane_for(payload, order="lsb", bit=2, width=8)
            _install_fake_rawpy(self, plane)

            result = extract_raw_lsb(
                raw_file,
                output,
                bit=2,
                order="lsb",
                crop=(4, 1, 8, 2),
            )

            self.assertEqual(result.crop, (4, 1, 8, 2))
            self.assertEqual(output.read_bytes(), payload)

    def test_scan_writes_magic_candidate_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_file = root / "sample.ARW"
            output_dir = root / "candidates"
            raw_file.write_bytes(b"fake raw")
            stream = b"\x00\x00PK\x03\x04ZIPDATA"
            _install_fake_rawpy(self, _plane_for(stream, order="msb"))

            result = scan_raw_lsb(
                raw_file,
                output_dir,
                bits=[0],
                orders=["msb"],
                max_bytes=len(stream),
                search_window=8,
            )

            self.assertEqual(result.operation, "image.raw-lsb.scan")
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0]["offset"], 2)
            candidate = Path(result.findings[0]["output_path"])
            self.assertTrue(candidate.name.startswith("bit0-msb-off2-zip"))
            self.assertTrue(candidate.read_bytes().startswith(b"PK\x03\x04"))
            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["findings"][0]["kind"], "zip")

    def test_cli_extract_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_file = root / "sample.ARW"
            output = root / "out.bin"
            raw_file.write_bytes(b"fake raw")
            _install_fake_rawpy(self, _plane_for(b"flag{raw}", order="msb"))

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "raw-lsb",
                        "extract",
                        str(raw_file),
                        "--bit",
                        "0",
                        "--order",
                        "msb",
                        "-o",
                        str(output),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.raw-lsb.extract")
            self.assertEqual(output.read_bytes(), b"flag{raw}")


def _install_fake_rawpy(testcase: unittest.TestCase, plane: np.ndarray) -> None:
    old = sys.modules.get("rawpy")
    module = types.ModuleType("rawpy")

    class FakeRaw:
        raw_image_visible = plane
        raw_image = plane

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    module.imread = lambda path: FakeRaw()  # type: ignore[attr-defined]
    sys.modules["rawpy"] = module

    def cleanup() -> None:
        if old is None:
            sys.modules.pop("rawpy", None)
        else:
            sys.modules["rawpy"] = old

    testcase.addCleanup(cleanup)


def _plane_for(payload: bytes, *, order: str, bit: int = 0, width: int = 8) -> np.ndarray:
    values: list[int] = []
    for byte in payload:
        bit_range = range(7, -1, -1) if order == "msb" else range(8)
        for bit_index in bit_range:
            values.append(((byte >> bit_index) & 1) << bit)
    while len(values) % width:
        values.append(0)
    return np.array(values, dtype=np.uint16).reshape(len(values) // width, width)


if __name__ == "__main__":
    unittest.main()
