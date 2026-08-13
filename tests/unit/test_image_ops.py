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
from oh_my_misc.image_ops import (
    COMBINE_OPERATIONS,
    combine_images,
    flip_image,
    join_images,
    sample_pixels,
    split_frames,
    split_grid,
)


class ImageOperationTest(unittest.TestCase):
    def test_split_and_join_animation_frames(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "animation.gif"
            frames = [Image.new("RGB", (4, 3), color) for color in ("red", "green", "blue")]
            frames[0].save(source, save_all=True, append_images=frames[1:], duration=50, loop=0)

            split_result = split_frames(source, root / "frames")
            join_result = join_images(
                [Path(path) for path in split_result.output_paths],
                root / "joined.png",
            )

            self.assertEqual(split_result.count, 3)
            self.assertEqual(join_result.count, 3)
            with Image.open(root / "joined.png") as joined:
                self.assertEqual(joined.size, (12, 3))

    def test_grid_split_and_natural_order_join(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "grid.png"
            pixels = np.zeros((4, 6, 3), dtype=np.uint8)
            pixels[:2, :3] = (255, 0, 0)
            pixels[:2, 3:] = (0, 255, 0)
            pixels[2:, :3] = (0, 0, 255)
            pixels[2:, 3:] = (255, 255, 0)
            Image.fromarray(pixels, "RGB").save(source)

            result = split_grid(source, root / "tiles", columns=2, rows=2)
            ordered = [Path(result.output_paths[index]) for index in (0, 1, 2, 3)]
            join_images(ordered, root / "joined.png", columns=2)

            with Image.open(root / "joined.png") as joined:
                np.testing.assert_array_equal(np.array(joined.convert("RGB")), pixels)

    def test_flip_both_axes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            pixels = np.arange(18, dtype=np.uint8).reshape(2, 3, 3)
            Image.fromarray(pixels, "RGB").save(source)

            flip_image(source, root / "horizontal.png", axis="horizontal")
            flip_image(source, root / "vertical.png", axis="vertical")

            with Image.open(root / "horizontal.png") as horizontal:
                np.testing.assert_array_equal(
                    np.array(horizontal.convert("RGB")), pixels[:, ::-1]
                )
            with Image.open(root / "vertical.png") as vertical:
                np.testing.assert_array_equal(np.array(vertical.convert("RGB")), pixels[::-1])

    def test_sample_equidistant_pixels_and_nearest_scale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            pixels = np.arange(8 * 10 * 3, dtype=np.uint8).reshape(8, 10, 3)
            Image.fromarray(pixels, "RGB").save(source)

            result = sample_pixels(
                source,
                root / "sampled.png",
                start_x=1,
                start_y=2,
                end_x=9,
                end_y=7,
                step_x=3,
                step_y=2,
                scale=4,
            )

            expected = pixels[2:8:2, 1:10:3]
            with Image.open(result.output_path) as sampled:
                actual = np.asarray(sampled.convert("RGB"))
            np.testing.assert_array_equal(actual[::4, ::4], expected)
            self.assertEqual((result.width, result.height), (12, 12))
            self.assertEqual(result.count, 9)

    def test_sample_defaults_to_inclusive_bottom_right(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            pixels = np.arange(7 * 9 * 3, dtype=np.uint8).reshape(7, 9, 3)
            Image.fromarray(pixels, "RGB").save(source)

            sample_pixels(source, root / "sampled.png", step_x=4, step_y=3)

            with Image.open(root / "sampled.png") as sampled:
                np.testing.assert_array_equal(
                    np.asarray(sampled.convert("RGB")), pixels[0:7:3, 0:9:4]
                )

    def test_sample_cli_accepts_blog_coordinate_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            Image.new("RGB", (25, 25), "red").save(source)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "sample",
                        str(source),
                        "--start",
                        "0x0",
                        "--end",
                        "24x24",
                        "--step",
                        "12x12",
                        "--scale",
                        "3",
                        "--output",
                        str(root / "sampled.png"),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual((payload["width"], payload["height"]), (9, 9))
            self.assertEqual(payload["count"], 9)

    def test_sample_rejects_out_of_bounds_range(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            Image.new("RGB", (5, 5), "red").save(source)

            with self.assertRaisesRegex(ValueError, "超出图片边界"):
                sample_pixels(source, root / "sampled.png", end_x=5, step_x=2, step_y=2)

    def test_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            Image.new("RGB", (6, 4), "red").save(source)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "split",
                        "grid",
                        str(source),
                        "--columns",
                        "2",
                        "--rows",
                        "2",
                        "--output",
                        str(root / "tiles"),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.split.grid")
            self.assertEqual(payload["count"], 4)

    def test_combine_stegsolve_arithmetic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.png"
            second = root / "second.png"
            Image.new("RGB", (1, 1), (255, 0, 1)).save(first)
            Image.new("RGB", (1, 1), (1, 2, 3)).save(second)
            expected = {
                "xor": (254, 2, 2),
                "add": (0, 2, 4),
                "add-rgb": (0, 2, 4),
                "sub": (253, 253, 254),
                "sub-rgb": (254, 254, 254),
                "mul": (254, 2, 3),
                "mul-rgb": (255, 0, 3),
                "lightest": (255, 2, 3),
                "darkest": (1, 0, 1),
            }
            for operation, pixel in expected.items():
                output = root / f"{operation}.png"
                combine_images(first, second, output, operation=operation)
                with Image.open(output) as image:
                    self.assertEqual(image.getpixel((0, 0)), pixel)

    def test_combine_interlace_and_all(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.png"
            second = root / "second.png"
            Image.new("RGB", (3, 2), "red").save(first)
            Image.new("RGB", (2, 3), "blue").save(second)

            horizontal = combine_images(
                first, second, root / "horizontal.png", operation="interlace-h"
            )
            vertical = combine_images(
                first, second, root / "vertical.png", operation="interlace-v"
            )
            all_result = combine_images(first, second, root / "all", operation="all")

            self.assertEqual((horizontal.width, horizontal.height), (2, 4))
            self.assertEqual((vertical.width, vertical.height), (4, 2))
            self.assertEqual(all_result.count, len(COMBINE_OPERATIONS))
            self.assertEqual(len(list((root / "all").glob("*.png"))), 13)

    def test_combine_cli_xor_reveals_difference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.png"
            second = root / "second.png"
            output = root / "xor.png"
            first_pixels = np.zeros((8, 8, 3), dtype=np.uint8)
            second_pixels = first_pixels.copy()
            second_pixels[2:6, 3:5] = 255
            Image.fromarray(first_pixels, "RGB").save(first)
            Image.fromarray(second_pixels, "RGB").save(second)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "combine",
                        str(first),
                        str(second),
                        "--operation",
                        "xor",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            with Image.open(output) as image:
                pixels = np.array(image)
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.combine.xor")
            self.assertEqual(int(pixels[2:6, 3:5].min()), 255)
            self.assertEqual(int(pixels[:2].max()), 0)


class ArnoldTransformTest(unittest.TestCase):
    def test_encode_then_decode_restores_square_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            from oh_my_misc.image_ops import arnold_transform_image

            root = Path(directory)
            source = root / "source.png"
            encoded = root / "encoded.png"
            decoded = root / "decoded.png"
            pixels = np.arange(16 * 16 * 3, dtype=np.uint8).reshape(16, 16, 3)
            Image.fromarray(pixels, "RGB").save(source)

            arnold_transform_image(source, encoded, action="encode", rounds=5, a=2, b=3)
            result = arnold_transform_image(encoded, decoded, action="decode", rounds=5, a=2, b=3)

            with Image.open(decoded) as image:
                np.testing.assert_array_equal(np.array(image.convert("RGB")), pixels)
            self.assertEqual(result.operation, "image.arnold.decode")
            self.assertEqual(result.count, 5)

    def test_arnold_brute_outputs_candidate_grid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            from oh_my_misc.image_ops import brute_arnold_images

            root = Path(directory)
            source = root / "source.png"
            Image.new("RGB", (4, 4), "white").save(source)

            result = brute_arnold_images(
                source,
                root / "candidates",
                rounds_range=range(1, 3),
                a_range=range(1, 3),
                b_range=range(1, 3),
            )

            self.assertEqual(result.operation, "image.arnold.brute.decode")
            self.assertEqual(result.count, 8)
            self.assertEqual(len(list((root / "candidates").glob("*.png"))), 8)

    def test_arnold_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            output = root / "encoded.png"
            Image.new("RGB", (8, 8), "black").save(source)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "arnold",
                        "encode",
                        str(source),
                        "--rounds",
                        "1",
                        "--a",
                        "2",
                        "--b",
                        "3",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.arnold.encode")
            self.assertTrue(output.is_file())


class MosaicDepixTest(unittest.TestCase):
    def test_pixelate_and_depix_with_search_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            from oh_my_misc.image_ops import depixelize_mosaic, pixelate_image

            root = Path(directory)
            source = root / "source.png"
            mosaic = root / "mosaic.png"
            restored = root / "restored.png"
            pixels = np.zeros((8, 8, 3), dtype=np.uint8)
            for row in range(2):
                for column in range(2):
                    y, x = row * 4, column * 4
                    base = np.array([40 + row * 90, 50 + column * 80, 80 + (row + column) * 50], dtype=np.uint8)
                    block = np.tile(base, (4, 4, 1))
                    block[1:3, 1:3] = np.clip(base.astype(int) + [20, 10, 5], 0, 255)
                    pixels[y : y + 4, x : x + 4] = block
            Image.fromarray(pixels, "RGB").save(source)

            pixelate = pixelate_image(source, mosaic, block_width=4)
            depix = depixelize_mosaic(mosaic, source, restored, block_width=4)

            with Image.open(restored) as image:
                np.testing.assert_array_equal(np.array(image.convert("RGB")), pixels)
            self.assertEqual(pixelate.operation, "image.mosaic.pixelate")
            self.assertEqual(depix.operation, "image.mosaic.depix")
            self.assertEqual(depix.matched, 4)
            self.assertEqual(depix.unmatched, 0)

    def test_mosaic_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            mosaic = root / "mosaic.png"
            restored = root / "restored.png"
            pixels = np.zeros((8, 8, 3), dtype=np.uint8)
            pixels[:4, :4] = (60, 80, 100)
            pixels[:4, 4:] = (120, 90, 30)
            pixels[4:, :4] = (30, 150, 70)
            pixels[4:, 4:] = (200, 40, 160)
            Image.fromarray(pixels, "RGB").save(source)
            main(["image", "mosaic", "pixelate", str(source), "--block-width", "4", "--output", str(mosaic)])

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "mosaic",
                        "depix",
                        str(mosaic),
                        "--search",
                        str(source),
                        "--block-width",
                        "4",
                        "--output",
                        str(restored),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.mosaic.depix")
            self.assertEqual(payload["matched"], 4)
            self.assertTrue(restored.is_file())



if __name__ == "__main__":
    unittest.main()
