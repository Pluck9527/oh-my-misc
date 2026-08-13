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
from oh_my_misc.puzzle import analyze_puzzle, solve_puzzle


class PuzzleTest(unittest.TestCase):
    def test_exact_solver_restores_shuffled_tiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            pixels = _continuous_image(96, 72)
            Image.fromarray(pixels, "RGB").save(source)
            paths = _write_shuffled_tiles(root, pixels, rows=3, columns=3)

            result = solve_puzzle(
                paths,
                root / "solved.png",
                rows=3,
                columns=3,
                algorithm="exact",
            )

            with Image.open(result.output_path) as solved:
                np.testing.assert_array_equal(np.asarray(solved.convert("RGB")), pixels)
            manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
            self.assertEqual(result.algorithm, "exact")
            self.assertEqual([item["source_index"] for item in manifest["placements"]], [5, 2, 8, 1, 7, 0, 6, 4, 3])

    def test_analyze_sheet_and_solve_with_tile_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pixels = _continuous_image(72, 48)
            tile_height, tile_width = 24, 24
            pieces = [
                pixels[row * tile_height : (row + 1) * tile_height, column * tile_width : (column + 1) * tile_width]
                for row in range(2)
                for column in range(3)
            ]
            order = [4, 1, 5, 2, 0, 3]
            sheet = np.concatenate(
                [np.concatenate([pieces[index] for index in order[:3]], axis=1), np.concatenate([pieces[index] for index in order[3:]], axis=1)],
                axis=0,
            )
            sheet_path = root / "sheet.png"
            Image.fromarray(sheet, "RGB").save(sheet_path)

            analysis = analyze_puzzle([sheet_path], tile_size=24)
            result = solve_puzzle(
                [sheet_path],
                root / "solved.png",
                rows=2,
                columns=3,
                tile_size=24,
                algorithm="exact",
            )

            self.assertEqual(analysis.count, 6)
            self.assertIn({"rows": 2, "columns": 3}, analysis.candidate_grids)
            with Image.open(result.output_path) as solved:
                np.testing.assert_array_equal(np.asarray(solved.convert("RGB")), pixels)

    def test_cli_json_reports_output_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pixels = _continuous_image(64, 64)
            paths = _write_shuffled_tiles(root, pixels, rows=2, columns=2)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "puzzle",
                        "solve",
                        *map(str, paths),
                        "--rows",
                        "2",
                        "--columns",
                        "2",
                        "--output",
                        str(root / "solved.png"),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.puzzle.solve")
            self.assertTrue(Path(payload["output_path"]).is_file())
            self.assertTrue(Path(payload["manifest_path"]).is_file())

    def test_rotation_search_restores_square_tiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pixels = _continuous_image(64, 64)
            paths = _write_shuffled_tiles(root, pixels, rows=2, columns=2, rotations=[1, 2, 3, 0])

            result = solve_puzzle(
                paths,
                root / "solved.png",
                rows=2,
                columns=2,
                rotate="90",
                algorithm="exact",
            )

            with Image.open(result.output_path) as solved:
                solved_pixels = np.asarray(solved.convert("RGB"))
            manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
            self.assertTrue(
                any(
                    np.array_equal(solved_pixels, np.rot90(pixels, rotation))
                    for rotation in range(4)
                )
            )
            self.assertIn(
                [item["rotation"] for item in manifest["placements"]],
                ([90, 180, 270, 0], [0, -90, -180, -270]),
            )

    def test_rejects_mismatched_tile_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for index in range(3):
                path = root / f"tile-{index}.png"
                Image.new("RGB", (8, 8), (index, 0, 0)).save(path)
                paths.append(path)

            with self.assertRaisesRegex(ValueError, "需要 4 块"):
                solve_puzzle(paths, root / "solved.png", rows=2, columns=2)


def _continuous_image(width: int, height: int) -> np.ndarray:
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    for offset in range(-height, width, 7):
        draw.line((offset, 0, offset + height, height), fill=(offset % 251, 80, 220), width=3)
    draw.ellipse((5, 4, width - 7, height - 5), outline=(20, 190, 30), width=4)
    draw.line((0, height // 2, width, height // 3), fill=(240, 30, 20), width=5)
    return np.asarray(image)


def _write_shuffled_tiles(
    root: Path,
    pixels: np.ndarray,
    *,
    rows: int,
    columns: int,
    rotations: list[int] | None = None,
) -> list[Path]:
    height, width = pixels.shape[:2]
    tile_height, tile_width = height // rows, width // columns
    pieces = [
        pixels[row * tile_height : (row + 1) * tile_height, column * tile_width : (column + 1) * tile_width]
        for row in range(rows)
        for column in range(columns)
    ]
    order = [5, 3, 1, 8, 7, 0, 6, 4, 2] if len(pieces) == 9 else [1, 3, 0, 2]
    rotations = rotations or [0] * len(pieces)
    paths = []
    for output_index, source_index in enumerate(order):
        path = root / f"piece-{output_index}.png"
        Image.fromarray(np.rot90(pieces[source_index], rotations[output_index]), "RGB").save(path)
        paths.append(path)
    return paths


if __name__ == "__main__":
    unittest.main()
