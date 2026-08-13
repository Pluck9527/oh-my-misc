from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.watermark import (
    embed_dual_watermark,
    embed_single_watermark,
    embed_ww23_watermark,
    extract_dual_watermark,
    extract_single_watermark,
    extract_ww23_watermark,
)


class SingleWatermarkTest(unittest.TestCase):
    def test_embed_and_extract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            embedded = root / "embedded.png"
            extracted = root / "extracted.png"
            pixels = np.zeros((64, 64, 3), dtype=np.uint8)
            pixels[:, :, 0] = np.arange(64, dtype=np.uint8)[None, :] * 3
            pixels[:, :, 1] = np.arange(64, dtype=np.uint8)[:, None] * 3
            pixels[:, :, 2] = 96
            Image.fromarray(pixels, "RGB").save(source)

            embedded_result = embed_single_watermark(
                source,
                embedded,
                "CTF",
                strength=25,
                font_size=18,
            )
            extracted_result = extract_single_watermark(embedded, extracted, brightness=5)

            original_pixels = np.array(Image.open(source).convert("RGB"))
            embedded_pixels = np.array(Image.open(embedded).convert("RGB"))
            extracted_pixels = np.array(Image.open(extracted).convert("RGB"))
            self.assertEqual(embedded_result.operation, "watermark.single.embed")
            self.assertEqual(extracted_result.operation, "watermark.single.extract")
            self.assertEqual(embedded_pixels.shape, original_pixels.shape)
            self.assertEqual(extracted_pixels.shape, original_pixels.shape)
            self.assertGreater(np.count_nonzero(embedded_pixels != original_pixels), 100)
            self.assertGreater(int(extracted_pixels.max()), 100)

    def test_size_schemes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            Image.new("RGB", (70, 50), (96, 128, 160)).save(source)

            best = embed_single_watermark(source, root / "best.png", "X", scheme="best")
            padded = embed_single_watermark(source, root / "pad.png", "X", scheme="pad")
            partial = embed_single_watermark(source, root / "partial.png", "X", scheme="partial")

            self.assertEqual((best.width, best.height), (64, 64))
            self.assertEqual((padded.width, padded.height), (70, 50))
            self.assertEqual((padded.work_width, padded.work_height), (128, 64))
            self.assertEqual((partial.width, partial.height), (70, 50))
            self.assertEqual((partial.work_width, partial.work_height), (64, 32))

    def test_rgba_alpha_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            embedded = root / "embedded.png"
            extracted = root / "extracted.png"
            pixels = np.full((32, 32, 4), 128, dtype=np.uint8)
            pixels[:, :, 3] = np.arange(32, dtype=np.uint8)[None, :] * 8
            Image.fromarray(pixels, "RGBA").save(source)

            embed_single_watermark(source, embedded, "A", font_size=12)
            extract_single_watermark(embedded, extracted)

            expected_alpha = np.array(Image.open(source).getchannel("A"))
            embedded_alpha = np.array(Image.open(embedded).getchannel("A"))
            extracted_alpha = np.array(Image.open(extracted).getchannel("A"))
            np.testing.assert_array_equal(embedded_alpha, expected_alpha)
            np.testing.assert_array_equal(extracted_alpha, expected_alpha)

    def test_json_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            output = root / "watermarked.png"
            Image.new("RGB", (32, 32), "gray").save(source)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "watermark",
                        "single",
                        "watermarkh",
                        "embed",
                        str(source),
                        "--output",
                        str(output),
                        "--text",
                        "flag",
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["status"], "success")
            self.assertEqual(payload["operation"], "watermark.single.embed")
            self.assertTrue(output.is_file())


class DualWatermarkTest(unittest.TestCase):
    def test_embed_and_extract_for_both_variants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            watermark = root / "watermark.png"
            source_pixels = np.zeros((64, 96, 3), dtype=np.uint8)
            source_pixels[:, :, 0] = np.arange(96, dtype=np.uint8)[None, :] * 2
            source_pixels[:, :, 1] = np.arange(64, dtype=np.uint8)[:, None] * 3
            source_pixels[:, :, 2] = 96
            watermark_pixels = np.zeros((12, 20, 3), dtype=np.uint8)
            watermark_pixels[2:10, 3:17] = (255, 128, 64)
            Image.fromarray(source_pixels, "RGB").save(source)
            Image.fromarray(watermark_pixels, "RGB").save(watermark)

            for variant in ("chishaxie", "linyacool"):
                embedded = root / f"embedded-{variant}.png"
                extracted = root / f"extracted-{variant}.png"
                embed_result = embed_dual_watermark(
                    source,
                    watermark,
                    embedded,
                    variant=variant,
                )
                extract_result = extract_dual_watermark(
                    source,
                    embedded,
                    extracted,
                    variant=variant,
                    watermark_size=(20, 12),
                )

                recovered = np.array(Image.open(extracted).convert("RGB"))
                self.assertEqual(embed_result.operation, "watermark.dual.embed")
                self.assertEqual(extract_result.operation, "watermark.dual.extract")
                self.assertEqual(recovered.shape, watermark_pixels.shape)
                self.assertGreater(
                    float(recovered[2:10, 3:17].mean()),
                    float(recovered[:2].mean()) * 5,
                )

    def test_json_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            watermark = root / "watermark.png"
            embedded = root / "embedded.png"
            Image.new("RGB", (64, 64), (80, 100, 120)).save(source)
            Image.new("RGB", (16, 16), "white").save(watermark)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "watermark",
                        "dual",
                        "linyacool",
                        "embed",
                        str(source),
                        "--watermark",
                        str(watermark),
                        "--output",
                        str(embedded),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "watermark.dual.embed")
            self.assertEqual(payload["variant"], "linyacool")
            self.assertEqual(payload["seed"], 128)
            self.assertEqual(payload["alpha"], 5.0)
            self.assertTrue(embedded.is_file())

    def test_rejects_reference_size_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "reference.png"
            embedded = root / "embedded.png"
            Image.new("RGB", (64, 64)).save(reference)
            Image.new("RGB", (63, 64)).save(embedded)
            with self.assertRaisesRegex(ValueError, "尺寸必须一致"):
                extract_dual_watermark(reference, embedded, root / "out.png")


class Ww23WatermarkTest(unittest.TestCase):
    def test_embed_and_blind_extract_for_both_transforms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            watermark = root / "watermark.png"
            source_pixels = np.zeros((64, 96, 3), dtype=np.uint8)
            source_pixels[:, :, 0] = np.arange(96, dtype=np.uint8)[None, :] * 2
            source_pixels[:, :, 1] = np.arange(64, dtype=np.uint8)[:, None] * 3
            source_pixels[:, :, 2] = 96
            watermark_pixels = np.zeros((16, 30), dtype=np.uint8)
            watermark_pixels[3:13, 4:26] = 255
            Image.fromarray(source_pixels, "RGB").save(source)
            Image.fromarray(watermark_pixels, "L").save(watermark)

            for transform in ("dct", "dft"):
                embedded = root / f"embedded-{transform}.png"
                extracted = root / f"extracted-{transform}.png"
                embed_result = embed_ww23_watermark(
                    source,
                    watermark,
                    embedded,
                    transform=transform,
                )
                extract_result = extract_ww23_watermark(
                    embedded,
                    extracted,
                    transform=transform,
                )

                carrier = np.array(Image.open(source).convert("RGB"), dtype=np.int16)
                encoded = np.array(Image.open(embedded).convert("RGB"), dtype=np.int16)
                recovered = np.array(Image.open(extracted))
                self.assertEqual(embed_result.operation, "watermark.ww23.embed")
                self.assertEqual(extract_result.operation, "watermark.ww23.extract")
                self.assertGreater(np.count_nonzero(carrier != encoded), 0)
                self.assertGreater(int(recovered.max()), int(recovered.min()))

    def test_json_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            watermark = root / "watermark.png"
            output = root / "embedded.png"
            Image.new("RGB", (64, 64), (80, 100, 120)).save(source)
            Image.new("L", (20, 10), 255).save(watermark)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "watermark",
                        "dual",
                        "ww23-dct",
                        "embed",
                        str(source),
                        "--watermark",
                        str(watermark),
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "watermark.ww23.embed")
            self.assertEqual(payload["transform"], "dct")
            self.assertEqual(payload["alpha"], 0.03)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
