from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import numpy as np
from PIL import Image

PuzzleAlgorithm = Literal["auto", "exact", "genetic", "greedy"]
PuzzleRotation = Literal["none", "90"]


@dataclass(frozen=True)
class PuzzleAnalysisResult:
    operation: str
    input_paths: list[str]
    count: int
    tile_width: int
    tile_height: int
    uniform_size: bool
    candidate_grids: list[dict[str, int]]

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class PuzzleSolveResult:
    operation: str
    output_path: str
    manifest_path: str
    input_paths: list[str]
    width: int
    height: int
    tile_width: int
    tile_height: int
    rows: int
    columns: int
    count: int
    algorithm: str
    score: float
    normalized_score: float
    confidence: float
    seed: int
    rotations: bool

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def analyze_puzzle(
    input_paths: list[Path],
    *,
    tile_size: int | None = None,
    tile_width: int | None = None,
    tile_height: int | None = None,
) -> PuzzleAnalysisResult:
    paths = _require_input_paths(input_paths)
    resolved_width, resolved_height = _resolve_tile_size(tile_size, tile_width, tile_height)
    images = _read_images(paths)
    if len(images) == 1 and resolved_width is not None:
        if images[0].width % resolved_width or images[0].height % resolved_height:
            raise ValueError("图片宽高必须能被切片宽高整除")
        count = images[0].width // resolved_width * (images[0].height // resolved_height)
        width, height, uniform = resolved_width, resolved_height, True
    else:
        if resolved_width is not None:
            raise ValueError("--tile-size/--tile-width 只用于单张拼图蒙太奇")
        count = len(images)
        width, height = images[0].size
        uniform = all(image.size == images[0].size for image in images)
    candidates = [
        {"rows": rows, "columns": count // rows}
        for rows in range(1, math.isqrt(count) + 1)
        if count % rows == 0
        for rows in ({rows, count // rows} if rows != count // rows else {rows})
    ]
    candidates.sort(key=lambda item: (abs(item["rows"] - item["columns"]), item["rows"]))
    return PuzzleAnalysisResult(
        operation="image.puzzle.analyze",
        input_paths=[str(path) for path in paths],
        count=count,
        tile_width=width,
        tile_height=height,
        uniform_size=uniform,
        candidate_grids=candidates,
    )


def solve_puzzle(
    input_paths: list[Path],
    output_path: Path,
    *,
    rows: int,
    columns: int,
    tile_size: int | None = None,
    tile_width: int | None = None,
    tile_height: int | None = None,
    algorithm: PuzzleAlgorithm = "auto",
    rotate: PuzzleRotation = "none",
    generations: int = 200,
    population: int = 0,
    edge_width: int = 2,
    seed: int = 0,
    manifest_path: Path | None = None,
) -> PuzzleSolveResult:
    if rows < 1 or columns < 1:
        raise ValueError("行数和列数必须大于 0")
    if algorithm not in {"auto", "exact", "genetic", "greedy"}:
        raise ValueError(f"未知拼图算法：{algorithm}")
    if rotate not in {"none", "90"}:
        raise ValueError(f"未知旋转模式：{rotate}")
    if generations < 1:
        raise ValueError("迭代代数必须大于 0")
    if population < 0:
        raise ValueError("种群数量不能小于 0")
    if edge_width < 1:
        raise ValueError("边缘采样宽度必须大于 0")

    paths = _require_input_paths(input_paths)
    resolved_width, resolved_height = _resolve_tile_size(tile_size, tile_width, tile_height)
    tiles = _load_tiles(paths, rows, columns, resolved_width, resolved_height)
    if rotate == "90" and tiles[0].width != tiles[0].height:
        raise ValueError("启用 90 度旋转时拼图块必须为正方形")
    rotation_count = 4 if rotate == "90" else 1
    right_costs, down_costs = _compatibility_matrices(tiles, rotation_count, edge_width)
    resolved_algorithm = _resolve_algorithm(algorithm, len(tiles), rotation_count)
    rng = np.random.default_rng(seed)
    greedy_layout, greedy_score = _greedy_layout(
        right_costs,
        down_costs,
        rows,
        columns,
        rotation_count,
        rng,
    )
    if resolved_algorithm == "exact":
        layout, score = _exact_layout(
            right_costs,
            down_costs,
            rows,
            columns,
            rotation_count,
            greedy_layout,
            greedy_score,
        )
    elif resolved_algorithm == "genetic":
        layout, score = _genetic_layout(
            right_costs,
            down_costs,
            rows,
            columns,
            rotation_count,
            rng,
            greedy_layout,
            generations,
            population,
        )
    else:
        layout, score = greedy_layout, greedy_score

    oriented = [
        tiles[int(state) // rotation_count].rotate(
            -90 * (int(state) % rotation_count), expand=True
        )
        for state in layout
    ]
    canvas = Image.new("RGBA", (columns * tiles[0].width, rows * tiles[0].height))
    for index, image in enumerate(oriented):
        row, column = divmod(index, columns)
        canvas.alpha_composite(image, (column * image.width, row * image.height))
    _save_image(canvas, output_path)

    adjacency_count = rows * (columns - 1) + columns * (rows - 1)
    normalized_score = score / max(1, adjacency_count)
    confidence = 1.0 / (1.0 + normalized_score * 4.0)
    resolved_manifest = manifest_path or output_path.with_suffix(".puzzle.json")
    placements = [
        {
            "row": index // columns,
            "column": index % columns,
            "source_index": int(state) // rotation_count,
            "source_path": str(paths[int(state) // rotation_count])
            if len(paths) > 1
            else str(paths[0]),
            "source_tile_index": int(state) // rotation_count if len(paths) == 1 else None,
            "rotation": -90 * (int(state) % rotation_count),
        }
        for index, state in enumerate(layout)
    ]
    resolved_manifest.parent.mkdir(parents=True, exist_ok=True)
    resolved_manifest.write_text(
        json.dumps(
            {
                "status": "success",
                "operation": "image.puzzle.solve",
                "algorithm": resolved_algorithm,
                "rows": rows,
                "columns": columns,
                "tile_width": tiles[0].width,
                "tile_height": tiles[0].height,
                "score": score,
                "normalized_score": normalized_score,
                "confidence": confidence,
                "seed": seed,
                "placements": placements,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return PuzzleSolveResult(
        operation="image.puzzle.solve",
        output_path=str(output_path),
        manifest_path=str(resolved_manifest),
        input_paths=[str(path) for path in paths],
        width=canvas.width,
        height=canvas.height,
        tile_width=tiles[0].width,
        tile_height=tiles[0].height,
        rows=rows,
        columns=columns,
        count=len(tiles),
        algorithm=resolved_algorithm,
        score=score,
        normalized_score=normalized_score,
        confidence=confidence,
        seed=seed,
        rotations=rotate == "90",
    )


def _require_input_paths(input_paths: list[Path]) -> list[Path]:
    if not input_paths:
        raise ValueError("至少需要一张输入图片")
    missing = next((path for path in input_paths if not path.is_file()), None)
    if missing is not None:
        raise FileNotFoundError(f"文件不存在：{missing}")
    return list(input_paths)


def _resolve_tile_size(
    tile_size: int | None,
    tile_width: int | None,
    tile_height: int | None,
) -> tuple[int | None, int | None]:
    if tile_size is not None and (tile_width is not None or tile_height is not None):
        raise ValueError("--tile-size 不能与 --tile-width/--tile-height 同时使用")
    if tile_size is not None:
        if tile_size < 1:
            raise ValueError("切片尺寸必须大于 0")
        return tile_size, tile_size
    if (tile_width is None) != (tile_height is None):
        raise ValueError("--tile-width 与 --tile-height 必须同时提供")
    if tile_width is not None and (tile_width < 1 or tile_height < 1):
        raise ValueError("切片宽高必须大于 0")
    return tile_width, tile_height


def _read_images(paths: list[Path]) -> list[Image.Image]:
    images = []
    for path in paths:
        with Image.open(path) as source:
            images.append(source.convert("RGBA"))
    return images


def _load_tiles(
    paths: list[Path],
    rows: int,
    columns: int,
    tile_width: int | None,
    tile_height: int | None,
) -> list[Image.Image]:
    images = _read_images(paths)
    expected = rows * columns
    if len(images) > 1:
        if tile_width is not None:
            raise ValueError("--tile-size/--tile-width 只用于单张拼图蒙太奇")
        if len(images) != expected:
            raise ValueError(f"输入了 {len(images)} 块，但 {rows} × {columns} 需要 {expected} 块")
        if any(image.size != images[0].size for image in images):
            raise ValueError("所有拼图块必须具有相同尺寸")
        return images

    sheet = images[0]
    if expected == 1:
        return images
    width = tile_width or sheet.width // columns
    height = tile_height or sheet.height // rows
    if sheet.width != width * columns or sheet.height != height * rows:
        raise ValueError("蒙太奇图片尺寸必须等于列数×块宽和行数×块高")
    return [
        sheet.crop((column * width, row * height, (column + 1) * width, (row + 1) * height))
        for row in range(rows)
        for column in range(columns)
    ]


def _compatibility_matrices(
    tiles: list[Image.Image], rotation_count: int, edge_width: int
) -> tuple[np.ndarray, np.ndarray]:
    arrays = [
        _premultiplied_pixels(np.rot90(np.asarray(tile), -rotation))
        for tile in tiles
        for rotation in range(rotation_count)
    ]
    count = len(arrays)
    right = np.full((count, count), np.inf, dtype=np.float64)
    down = np.full((count, count), np.inf, dtype=np.float64)
    for first in range(count):
        for second in range(count):
            if first // rotation_count == second // rotation_count:
                continue
            right[first, second] = _edge_cost(arrays[first], arrays[second], "right", edge_width)
            down[first, second] = _edge_cost(arrays[first], arrays[second], "down", edge_width)
    return right, down


def _premultiplied_pixels(pixels: np.ndarray) -> np.ndarray:
    values = pixels.astype(np.float64) / 255.0
    alpha = values[:, :, 3:4]
    return np.concatenate((values[:, :, :3] * alpha, alpha), axis=2)


def _edge_cost(
    first: np.ndarray, second: np.ndarray, direction: str, edge_width: int
) -> float:
    if direction == "down":
        first = np.swapaxes(first, 0, 1)
        second = np.swapaxes(second, 0, 1)
    if first.shape[0] != second.shape[0]:
        return math.inf
    width = min(edge_width, first.shape[1], second.shape[1])
    first_edge = first[:, -1]
    second_edge = second[:, 0]
    seam = np.mean(np.abs(first_edge - second_edge))
    if width == 1:
        return float(seam)
    first_gradient = np.mean(np.diff(first[:, -width:], axis=1), axis=1)
    second_gradient = np.mean(np.diff(second[:, :width], axis=1), axis=1)
    seam_gradient = second_edge - first_edge
    smoothness = np.mean(
        np.abs(seam_gradient - first_gradient) + np.abs(second_gradient - seam_gradient)
    )
    return float(seam + smoothness * 0.5)


def _resolve_algorithm(algorithm: PuzzleAlgorithm, count: int, rotations: int) -> str:
    exact_limit = 9 if rotations == 1 else 7
    if algorithm == "auto":
        return "exact" if count <= exact_limit else "genetic"
    if algorithm == "exact" and count > exact_limit:
        raise ValueError(f"精确搜索最多支持 {exact_limit} 块；请使用 genetic")
    return algorithm


def _layout_score(
    layout: np.ndarray,
    right: np.ndarray,
    down: np.ndarray,
    rows: int,
    columns: int,
) -> float:
    grid = layout.reshape(rows, columns)
    horizontal = right[grid[:, :-1], grid[:, 1:]].sum() if columns > 1 else 0.0
    vertical = down[grid[:-1], grid[1:]].sum() if rows > 1 else 0.0
    return float(horizontal + vertical)


def _greedy_layout(
    right: np.ndarray,
    down: np.ndarray,
    rows: int,
    columns: int,
    rotations: int,
    rng: np.random.Generator,
) -> tuple[np.ndarray, float]:
    tile_count = rows * columns
    state_count = tile_count * rotations
    starts = np.arange(state_count)
    if state_count > 64:
        starts = rng.choice(starts, 64, replace=False)
    best_layout = np.arange(tile_count, dtype=np.int64) * rotations
    best_score = math.inf
    for start in starts:
        layout = [int(start)]
        used = {int(start) // rotations}
        for position in range(1, tile_count):
            candidates = []
            for tile in range(tile_count):
                if tile in used:
                    continue
                for rotation in range(rotations):
                    state = tile * rotations + rotation
                    cost = 0.0
                    if position % columns:
                        cost += right[layout[position - 1], state]
                    if position >= columns:
                        cost += down[layout[position - columns], state]
                    candidates.append((float(cost), state))
            _, selected = min(candidates)
            layout.append(selected)
            used.add(selected // rotations)
        candidate = np.asarray(layout, dtype=np.int64)
        score = _layout_score(candidate, right, down, rows, columns)
        if score < best_score:
            best_layout, best_score = candidate, score
    return best_layout, best_score


def _exact_layout(
    right: np.ndarray,
    down: np.ndarray,
    rows: int,
    columns: int,
    rotations: int,
    initial_layout: np.ndarray,
    initial_score: float,
) -> tuple[np.ndarray, float]:
    tile_count = rows * columns
    best_layout = initial_layout.copy()
    best_score = initial_score
    layout = np.empty(tile_count, dtype=np.int64)
    used = np.zeros(tile_count, dtype=np.bool_)

    def search(position: int, score: float) -> None:
        nonlocal best_layout, best_score
        if score >= best_score:
            return
        if position == tile_count:
            best_layout, best_score = layout.copy(), score
            return
        candidates = []
        for tile in np.flatnonzero(~used):
            for rotation in range(rotations):
                state = int(tile) * rotations + rotation
                cost = 0.0
                if position % columns:
                    cost += right[layout[position - 1], state]
                if position >= columns:
                    cost += down[layout[position - columns], state]
                candidates.append((float(cost), state, int(tile)))
        for cost, state, tile in sorted(candidates):
            layout[position] = state
            used[tile] = True
            search(position + 1, score + cost)
            used[tile] = False

    search(0, 0.0)
    return best_layout, best_score


def _genetic_layout(
    right: np.ndarray,
    down: np.ndarray,
    rows: int,
    columns: int,
    rotations: int,
    rng: np.random.Generator,
    greedy_layout: np.ndarray,
    generations: int,
    population: int,
) -> tuple[np.ndarray, float]:
    tile_count = rows * columns
    population_size = population or min(240, max(48, tile_count * 2))
    population_size = max(4, population_size)
    layouts = [greedy_layout.copy()]
    while len(layouts) < population_size:
        tiles = rng.permutation(tile_count)
        orientations = rng.integers(0, rotations, tile_count) if rotations > 1 else 0
        layouts.append((tiles * rotations + orientations).astype(np.int64))

    scores = np.asarray(
        [_layout_score(layout, right, down, rows, columns) for layout in layouts]
    )
    elite_count = max(2, population_size // 10)
    for _ in range(generations):
        elite_indices = np.argsort(scores)[:elite_count]
        next_layouts = [layouts[int(index)].copy() for index in elite_indices]
        while len(next_layouts) < population_size:
            parents = []
            for _ in range(2):
                tournament = rng.choice(population_size, min(4, population_size), replace=False)
                parents.append(layouts[int(tournament[np.argmin(scores[tournament])])])
            start, stop = sorted(rng.choice(tile_count + 1, 2, replace=False))
            first_tiles = parents[0] // rotations
            second_tiles = parents[1] // rotations
            child_tiles = np.full(tile_count, -1, dtype=np.int64)
            child_tiles[start:stop] = first_tiles[start:stop]
            remaining = [tile for tile in second_tiles if tile not in child_tiles]
            child_tiles[child_tiles < 0] = remaining
            first_rotation = {int(state) // rotations: int(state) % rotations for state in parents[0]}
            second_rotation = {
                int(state) // rotations: int(state) % rotations for state in parents[1]
            }
            child = np.asarray(
                [
                    int(tile) * rotations
                    + (
                        first_rotation[int(tile)]
                        if rng.random() < 0.5
                        else second_rotation[int(tile)]
                    )
                    for tile in child_tiles
                ],
                dtype=np.int64,
            )
            if rng.random() < 0.8:
                first, second = rng.choice(tile_count, 2, replace=False)
                child[first], child[second] = child[second], child[first]
            if rotations > 1 and rng.random() < 0.5:
                position = int(rng.integers(tile_count))
                child[position] = child[position] // rotations * rotations + int(
                    rng.integers(rotations)
                )
            next_layouts.append(child)
        layouts = next_layouts
        scores = np.asarray(
            [_layout_score(layout, right, down, rows, columns) for layout in layouts]
        )

    best_index = int(np.argmin(scores))
    best = layouts[best_index].copy()
    best_score = float(scores[best_index])
    attempts = max(1000, tile_count * 30)
    for _ in range(attempts):
        candidate = best.copy()
        first, second = rng.choice(tile_count, 2, replace=False)
        candidate[first], candidate[second] = candidate[second], candidate[first]
        if rotations > 1 and rng.random() < 0.25:
            position = int(rng.integers(tile_count))
            candidate[position] = candidate[position] // rotations * rotations + int(
                rng.integers(rotations)
            )
        score = _layout_score(candidate, right, down, rows, columns)
        if score < best_score:
            best, best_score = candidate, score
    return best, best_score


def _save_image(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() in {".jpg", ".jpeg"}:
        image.convert("RGB").save(path, quality=100)
        return
    if path.suffix.lower() == ".bmp":
        image.convert("RGB").save(path)
        return
    if path.suffix.lower() == ".png":
        image.save(path)
        return
    raise ValueError("输出格式仅支持 PNG、JPEG 和 BMP")
