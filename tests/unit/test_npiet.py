from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.npiet import BLACK, PIET_PALETTE, detect_codel_size, run_piet


class NpietTest(unittest.TestCase):
    def test_reference_hi_program(self) -> None:
        """Run the 10×10 codel layout from npiet's official hi.png example."""
        layout = [
            [10, 10, 10, 16, 16, 16, -2, 8, 8, -2],
            [10, 10, 10, 16, 16, 8, 8, 8, 8, 8],
            [10, 10, 10, 16, 16, 16, 4, 17, 15, 8],
            [6, 6, 6, 6, -2, 6, 6, 9, 6, 8],
            [6, 6, 6, 6, 8, 15, 9, 9, 9, 8],
            [6, 6, 6, 6, 8, 6, 6, 9, 14, 8],
            [7, 7, -2, -2, 8, -2, -2, 9, 14, 14],
            [7, 7, -2, 8, 8, 8, -2, 9, 9, 2],
            [-2, -2, -2, -2, -2, -2, -2, -2, 9, 15],
            [7, 7, -2, 7, 7, 7, 7, -2, 9, 16],
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "hi.png"
            image = Image.new("RGB", (10, 10), BLACK)
            image.putdata(
                [BLACK if index == -2 else PIET_PALETTE[index] for row in layout for index in row]
            )
            image.save(source)

            result = run_piet(source)
            self.assertEqual(result.stdout, "Hi\n")
            self.assertEqual(result.steps, 12)
            self.assertTrue(result.halted)

    def test_push_and_out_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "program.png"
            # 3 light-red codels -> red is push(3); red -> dark-magenta is out(number).
            image = Image.new("RGB", (5, 1), BLACK)
            image.putdata(
                [
                    PIET_PALETTE[0],
                    PIET_PALETTE[0],
                    PIET_PALETTE[0],
                    PIET_PALETTE[6],
                    PIET_PALETTE[17],
                ]
            )
            image.save(source)

            result = run_piet(source, max_steps=2)
            self.assertEqual(result.stdout, "3")
            self.assertFalse(result.halted)
            self.assertEqual(result.halt_reason, "达到 max_steps")

    def test_push_and_out_char_with_auto_codel_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scaled.png"
            codels = Image.new("RGB", (67, 1), PIET_PALETTE[0])
            pixels = [PIET_PALETTE[0]] * 65 + [PIET_PALETTE[6], PIET_PALETTE[5]]
            codels.putdata(pixels)
            codels.resize((67 * 4, 4), Image.Resampling.NEAREST).save(source)

            result = run_piet(source, max_steps=2)
            self.assertEqual(result.codel_size, 4)
            self.assertEqual(result.stdout, "A")

    def test_white_slide_executes_no_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "white.png"
            # The first transition normally means push, but the intervening white codel suppresses it.
            image = Image.new("RGB", (4, 1), BLACK)
            image.putdata([PIET_PALETTE[0], (255, 255, 255), PIET_PALETTE[6], BLACK])
            image.save(source)
            result = run_piet(source, max_steps=1)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stack, [])

    def test_white_region_turns_at_restrictions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "white-turn.png"
            # Right is blocked, so white traversal turns down, then left to the target.
            image = Image.new("RGB", (3, 2), BLACK)
            image.putpixel((0, 0), PIET_PALETTE[0])
            image.putpixel((1, 0), (255, 255, 255))
            image.putpixel((1, 1), (255, 255, 255))
            image.putpixel((0, 1), PIET_PALETTE[6])
            image.save(source)

            result = run_piet(source, max_steps=1, trace=True)
            self.assertEqual((result.trace or [])[0]["next_position"], (0, 1))
            self.assertEqual((result.trace or [])[0]["dp"], "left")

    def test_pointer_changes_direction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "pointer.png"
            # push 1, then pointer; the DP rotates down and reaches the codel below.
            image = Image.new("RGB", (3, 2), BLACK)
            image.putpixel((0, 0), PIET_PALETTE[0])
            image.putpixel((1, 0), PIET_PALETTE[6])
            image.putpixel((2, 0), PIET_PALETTE[15])
            image.putpixel((2, 1), PIET_PALETTE[16])
            image.save(source)
            result = run_piet(source, max_steps=3, trace=True)
            self.assertGreaterEqual(result.steps, 3)
            self.assertTrue(any(step["dp"] == "down" for step in result.trace or []))

    def test_detect_codel_size(self) -> None:
        image = Image.new("RGB", (6, 3), PIET_PALETTE[0])
        for y in range(3):
            for x in range(3, 6):
                image.putpixel((x, y), PIET_PALETTE[6])
        import numpy as np

        self.assertEqual(detect_codel_size(np.asarray(image)), 3)

    def test_cli_trace_json_and_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "program.png"
            trace_image = root / "trace.png"
            image = Image.new("RGB", (3, 1), BLACK)
            image.putdata([PIET_PALETTE[0], PIET_PALETTE[6], PIET_PALETTE[17]])
            image.save(source)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "piet",
                        str(source),
                        "--trace",
                        "--trace-image",
                        str(trace_image),
                        "--max-steps",
                        "2",
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.npiet.run")
            self.assertEqual(payload["stdout"], "1")
            self.assertTrue(payload["trace"])
            self.assertTrue(trace_image.is_file())


if __name__ == "__main__":
    unittest.main()
