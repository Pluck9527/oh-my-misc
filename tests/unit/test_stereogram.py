from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

from oh_my_misc.cli import main
from oh_my_misc.stereogram import solve_stereogram


class StereogramTest(unittest.TestCase):
    def test_known_offset_matches_stegsolve_xor_transform(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            pixels = np.arange(6 * 9 * 3, dtype=np.uint8).reshape(6, 9, 3)
            Image.fromarray(pixels, "RGB").save(source)

            result = solve_stereogram(source, root / "solved.png", offset=4)

            with Image.open(result.output_path) as solved:
                actual = np.asarray(solved.convert("RGB"))
            np.testing.assert_array_equal(actual, np.bitwise_xor(pixels, np.roll(pixels, -4, 1)))
            self.assertEqual(result.offset, 4)

    def test_invert_is_exact_inverse_of_stegsolve_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            pixels = np.arange(4 * 7 * 3, dtype=np.uint8).reshape(4, 7, 3)
            Image.fromarray(pixels, "RGB").save(source)

            solve_stereogram(source, root / "normal.png", offset=2)
            solve_stereogram(source, root / "inverted.png", offset=2, invert=True)

            with Image.open(root / "normal.png") as normal, Image.open(root / "inverted.png") as inverted:
                np.testing.assert_array_equal(
                    np.asarray(inverted), np.bitwise_xor(np.asarray(normal), 0xFF)
                )

    def test_scan_writes_stable_candidates_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            Image.new("RGB", (12, 5), "red").save(source)

            result = solve_stereogram(
                source,
                root / "scan",
                offset_start=3,
                offset_stop=7,
            )

            self.assertEqual(result.count, 4)
            self.assertEqual(
                [Path(path).name for path in result.output_paths],
                ["offset-003.png", "offset-004.png", "offset-005.png", "offset-006.png"],
            )
            manifest = json.loads(Path(result.manifest_path or "").read_text(encoding="utf-8"))
            self.assertEqual([item["offset"] for item in manifest["outputs"]], [3, 4, 5, 6])

    def test_generated_stereogram_reveals_depth_at_period(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            period = 24
            height, width = 48, 144
            rng = np.random.default_rng(20260812)
            pattern = rng.integers(0, 256, (height, period, 3), dtype=np.uint8)
            carrier = np.tile(pattern, (1, width // period, 1))
            mask = Image.new("1", (width, height))
            ImageDraw.Draw(mask).text((45, 16), "CTF", fill=1)
            hidden = np.asarray(mask, dtype=bool)
            carrier[hidden] = np.roll(carrier, -3, axis=1)[hidden]
            source = root / "stereogram.png"
            Image.fromarray(carrier, "RGB").save(source)

            solve_stereogram(source, root / "solved.png", offset=period)

            with Image.open(root / "solved.png") as solved:
                values = np.asarray(solved.convert("RGB"))
            self.assertGreater(float(values[hidden].mean()), float(values[~hidden].mean()) + 10)

    def test_cli_json_and_invalid_offset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            Image.new("RGB", (8, 6), "blue").save(source)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "stereogram",
                        str(source),
                        "--offset",
                        "3",
                        "--output",
                        str(root / "solved.png"),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.stereogram.solve")
            self.assertEqual(payload["offset"], 3)
            with self.assertRaisesRegex(ValueError, "0..7"):
                solve_stereogram(source, root / "invalid.png", offset=8)


if __name__ == "__main__":
    unittest.main()
