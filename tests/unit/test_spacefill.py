from __future__ import annotations

import contextlib
import io
import itertools
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.spacefill import spacefill_points, transform_spacefill_image


class SpaceFillCurveTest(unittest.TestCase):
    def test_peano_points_are_contiguous_and_complete(self) -> None:
        self._assert_curve_invariants("peano", order=3, side=27)

    def test_hilbert_points_are_contiguous_and_complete(self) -> None:
        self._assert_curve_invariants("hilbert", order=5, side=32)

    def test_peano_encode_decode_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            encoded = root / "encoded.png"
            decoded = root / "decoded.png"
            pixels = np.arange(9 * 9 * 3, dtype=np.uint8).reshape(9, 9, 3)
            Image.fromarray(pixels, "RGB").save(source)

            encode = transform_spacefill_image(source, encoded, curve="peano", action="encode")
            decode = transform_spacefill_image(encoded, decoded, curve="peano", action="decode")

            with Image.open(decoded) as image:
                np.testing.assert_array_equal(np.array(image.convert("RGB")), pixels)
            self.assertEqual(encode.order, 2)
            self.assertEqual(decode.operation, "image.spacefill.decode")
            self.assertEqual(decode.count, 81)

    def test_hilbert_encode_decode_roundtrip_with_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            encoded = root / "encoded.png"
            decoded = root / "decoded.png"
            pixels = np.arange(8 * 8 * 3, dtype=np.uint8).reshape(8, 8, 3)
            Image.fromarray(pixels, "RGB").save(source)

            transform_spacefill_image(
                source,
                encoded,
                curve="hilbert",
                action="encode",
                order=3,
                flip_y=False,
                reverse=True,
            )
            result = transform_spacefill_image(
                encoded,
                decoded,
                curve="hilbert",
                action="decode",
                order=3,
                flip_y=False,
                reverse=True,
            )

            with Image.open(decoded) as image:
                np.testing.assert_array_equal(np.array(image.convert("RGB")), pixels)
            self.assertEqual(result.curve, "hilbert")
            self.assertFalse(result.flip_y)
            self.assertTrue(result.reverse)

    def test_spacefill_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            output = root / "encoded.png"
            Image.new("RGB", (4, 4), "white").save(source)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "spacefill",
                        "encode",
                        str(source),
                        "--curve",
                        "hilbert",
                        "--order",
                        "2",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.spacefill.encode")
            self.assertEqual(payload["curve"], "hilbert")
            self.assertEqual(payload["side"], 4)
            self.assertTrue(output.is_file())

    def test_rejects_invalid_side_length(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.png"
            output = Path(directory) / "output.png"
            Image.new("RGB", (10, 10), "white").save(source)
            with self.assertRaisesRegex(ValueError, "不是 peano 曲线要求的"):
                transform_spacefill_image(source, output, curve="peano", action="decode")

    def _assert_curve_invariants(self, curve: str, *, order: int, side: int) -> None:
        points = spacefill_points(curve, order)
        self.assertEqual(len(points), side * side)
        self.assertEqual(len(set(points)), side * side)
        self.assertTrue(all(0 <= x < side and 0 <= y < side for x, y in points))
        self.assertTrue(
            all(
                abs(first_x - second_x) + abs(first_y - second_y) == 1
                for (first_x, first_y), (second_x, second_y) in itertools.pairwise(points)
            )
        )


if __name__ == "__main__":
    unittest.main()
