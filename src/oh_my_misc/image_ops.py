from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import numpy as np
from PIL import Image, ImageSequence

from oh_my_misc.spacefill import transform_spacefill_image as _transform_spacefill_image

spacefill_transform_image = _transform_spacefill_image

CombineOperation = Literal[
    "xor",
    "or",
    "and",
    "add",
    "add-rgb",
    "sub",
    "sub-rgb",
    "mul",
    "mul-rgb",
    "lightest",
    "darkest",
    "interlace-h",
    "interlace-v",
    "all",
]
COMBINE_OPERATIONS = (
    "xor",
    "or",
    "and",
    "add",
    "add-rgb",
    "sub",
    "sub-rgb",
    "mul",
    "mul-rgb",
    "lightest",
    "darkest",
    "interlace-h",
    "interlace-v",
)


@dataclass(frozen=True)
class ImageOperationResult:
    operation: str
    output_path: str
    width: int
    height: int
    input_paths: list[str]
    output_paths: list[str]
    count: int

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def split_frames(input_path: Path, output_dir: Path, *, prefix: str = "frame") -> ImageOperationResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if not prefix:
        raise ValueError("帧文件名前缀不能为空")
    output_dir.mkdir(parents=True, exist_ok=True)
    with Image.open(input_path) as source:
        frames = [frame.convert("RGBA") for frame in ImageSequence.Iterator(source)]
    if not frames:
        raise ValueError("图片中没有可提取的帧")
    digits = max(4, len(str(len(frames) - 1)))
    outputs = [output_dir / f"{prefix}-{index:0{digits}d}.png" for index in range(len(frames))]
    for frame, output in zip(frames, outputs, strict=True):
        frame.save(output)
    return ImageOperationResult(
        operation="image.split.frames",
        output_path=str(output_dir),
        width=frames[0].width,
        height=frames[0].height,
        input_paths=[str(input_path)],
        output_paths=[str(output) for output in outputs],
        count=len(outputs),
    )


def split_grid(
    input_path: Path,
    output_dir: Path,
    *,
    columns: int,
    rows: int,
    prefix: str = "tile",
) -> ImageOperationResult:
    if columns < 1 or rows < 1:
        raise ValueError("行数和列数必须大于 0")
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    if image.width % columns or image.height % rows:
        raise ValueError("图片宽高必须能被网格列数和行数整除")
    width = image.width // columns
    height = image.height // rows
    outputs = [
        output_dir / f"{prefix}-{row:03d}-{column:03d}.png"
        for row in range(rows)
        for column in range(columns)
    ]
    for index, output in enumerate(outputs):
        row, column = divmod(index, columns)
        image.crop(
            (column * width, row * height, (column + 1) * width, (row + 1) * height)
        ).save(output)
    return ImageOperationResult(
        operation="image.split.grid",
        output_path=str(output_dir),
        width=width,
        height=height,
        input_paths=[str(input_path)],
        output_paths=[str(output) for output in outputs],
        count=len(outputs),
    )


def join_images(
    input_paths: list[Path],
    output_path: Path,
    *,
    columns: int = 0,
    gap: int = 0,
    background: str = "transparent",
) -> ImageOperationResult:
    paths = sorted(input_paths, key=_natural_key)
    if not paths:
        raise ValueError("至少需要一张输入图片")
    missing = next((path for path in paths if not path.is_file()), None)
    if missing is not None:
        raise FileNotFoundError(f"文件不存在：{missing}")
    if columns < 0:
        raise ValueError("列数不能小于 0")
    if gap < 0:
        raise ValueError("间距不能小于 0")
    images: list[Image.Image] = []
    for path in paths:
        with Image.open(path) as source:
            images.append(source.convert("RGBA"))
    resolved_columns = columns or len(images)
    rows = (len(images) + resolved_columns - 1) // resolved_columns
    column_widths = [
        max(
            (image.width for index, image in enumerate(images) if index % resolved_columns == column),
            default=0,
        )
        for column in range(resolved_columns)
    ]
    row_heights = [
        max(images[index].height for index in range(row * resolved_columns, min((row + 1) * resolved_columns, len(images))))
        for row in range(rows)
    ]
    canvas = Image.new(
        "RGBA",
        (sum(column_widths) + gap * (resolved_columns - 1), sum(row_heights) + gap * (rows - 1)),
        (0, 0, 0, 0) if background == "transparent" else background,
    )
    x_offsets = [sum(column_widths[:column]) + gap * column for column in range(resolved_columns)]
    y_offsets = [sum(row_heights[:row]) + gap * row for row in range(rows)]
    for index, image in enumerate(images):
        row, column = divmod(index, resolved_columns)
        canvas.alpha_composite(image, (x_offsets[column], y_offsets[row]))
    _save_image(canvas, output_path)
    return ImageOperationResult(
        operation="image.join",
        output_path=str(output_path),
        width=canvas.width,
        height=canvas.height,
        input_paths=[str(path) for path in paths],
        output_paths=[str(output_path)],
        count=len(paths),
    )


def flip_image(input_path: Path, output_path: Path, *, axis: str) -> ImageOperationResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if axis not in {"horizontal", "vertical"}:
        raise ValueError(f"未知翻转方向：{axis}")
    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    result = image.transpose(
        Image.Transpose.FLIP_LEFT_RIGHT if axis == "horizontal" else Image.Transpose.FLIP_TOP_BOTTOM
    )
    _save_image(result, output_path)
    return ImageOperationResult(
        operation=f"image.flip.{axis}",
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        input_paths=[str(input_path)],
        output_paths=[str(output_path)],
        count=1,
    )


def sample_pixels(
    input_path: Path,
    output_path: Path,
    *,
    start_x: int = 0,
    start_y: int = 0,
    end_x: int | None = None,
    end_y: int | None = None,
    step_x: int = 1,
    step_y: int = 1,
    scale: int = 1,
) -> ImageOperationResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if start_x < 0 or start_y < 0:
        raise ValueError("起始坐标不能小于 0")
    if step_x < 1 or step_y < 1:
        raise ValueError("采样间距必须大于 0")
    if scale < 1:
        raise ValueError("近邻放大倍数必须大于 0")
    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    resolved_end_x = image.width - 1 if end_x is None else end_x
    resolved_end_y = image.height - 1 if end_y is None else end_y
    if resolved_end_x < start_x or resolved_end_y < start_y:
        raise ValueError("终止坐标不能小于起始坐标")
    if resolved_end_x >= image.width or resolved_end_y >= image.height:
        raise ValueError(f"采样范围超出图片边界：{image.width} × {image.height}")
    pixels = np.asarray(image)
    sampled = pixels[
        start_y : resolved_end_y + 1 : step_y,
        start_x : resolved_end_x + 1 : step_x,
    ]
    if not sampled.size:
        raise ValueError("指定范围内没有可提取的像素")
    result = Image.fromarray(sampled, "RGBA")
    if scale > 1:
        result = result.resize((result.width * scale, result.height * scale), Image.Resampling.NEAREST)
    _save_image(result, output_path)
    return ImageOperationResult(
        operation="image.sample",
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        input_paths=[str(input_path)],
        output_paths=[str(output_path)],
        count=sampled.shape[0] * sampled.shape[1],
    )


def arnold_transform_image(
    input_path: Path,
    output_path: Path,
    *,
    action: str,
    rounds: int,
    a: int,
    b: int,
) -> ImageOperationResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if action not in {"encode", "decode"}:
        raise ValueError(f"未知 Arnold 操作：{action}")
    if rounds < 0:
        raise ValueError("Arnold 变换轮数不能小于 0")
    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    pixels = np.asarray(image).copy()
    transformed = _arnold_pixels(pixels, rounds=rounds, a=a, b=b, inverse=action == "decode")
    result = Image.fromarray(transformed, "RGBA")
    _save_image(result, output_path)
    return ImageOperationResult(
        operation=f"image.arnold.{action}",
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        input_paths=[str(input_path)],
        output_paths=[str(output_path)],
        count=rounds,
    )


def brute_arnold_images(
    input_path: Path,
    output_dir: Path,
    *,
    rounds_range: range,
    a_range: range,
    b_range: range,
    action: str = "decode",
) -> ImageOperationResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if action not in {"encode", "decode"}:
        raise ValueError(f"未知 Arnold 操作：{action}")
    if not rounds_range or not a_range or not b_range:
        raise ValueError("爆破范围不能为空")
    output_dir.mkdir(parents=True, exist_ok=True)
    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    pixels = np.asarray(image).copy()
    outputs: list[Path] = []
    inverse = action == "decode"
    for rounds in rounds_range:
        if rounds < 0:
            raise ValueError("Arnold 变换轮数不能小于 0")
        for a_value in a_range:
            for b_value in b_range:
                transformed = _arnold_pixels(
                    pixels,
                    rounds=rounds,
                    a=a_value,
                    b=b_value,
                    inverse=inverse,
                )
                output = output_dir / f"{action}_r{rounds}_a{a_value}_b{b_value}.png"
                _save_image(Image.fromarray(transformed, "RGBA"), output)
                outputs.append(output)
    return ImageOperationResult(
        operation=f"image.arnold.brute.{action}",
        output_path=str(output_dir),
        width=image.width,
        height=image.height,
        input_paths=[str(input_path)],
        output_paths=[str(output) for output in outputs],
        count=len(outputs),
    )


def _arnold_pixels(
    pixels: np.ndarray,
    *,
    rounds: int,
    a: int,
    b: int,
    inverse: bool,
) -> np.ndarray:
    height, width = pixels.shape[:2]
    rows, columns = np.indices((height, width))
    current = pixels.copy()
    for _ in range(rounds):
        transformed = np.empty_like(current)
        if inverse:
            new_rows = ((a * b + 1) * rows - b * columns) % height
            new_columns = (-a * rows + columns) % width
        else:
            new_rows = (rows + b * columns) % height
            new_columns = (a * rows + (a * b + 1) * columns) % width
        transformed[new_rows, new_columns] = current[rows, columns]
        current = transformed
    return current


@dataclass(frozen=True)
class MosaicDepixResult(ImageOperationResult):
    blocks: int = 0
    matched: int = 0
    unmatched: int = 0
    average_type: str = "gammacorrected"

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def pixelate_image(
    input_path: Path,
    output_path: Path,
    *,
    block_width: int,
    block_height: int | None = None,
    average_type: str = "gammacorrected",
) -> ImageOperationResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if block_width < 1 or (block_height is not None and block_height < 1):
        raise ValueError("马赛克块宽高必须大于 0")
    resolved_block_height = block_width if block_height is None else block_height
    if average_type not in {"gammacorrected", "linear"}:
        raise ValueError(f"未知平均颜色类型：{average_type}")
    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    pixels = np.asarray(image).copy()
    result = pixels.copy()
    for y in range(0, image.height, resolved_block_height):
        for x in range(0, image.width, block_width):
            patch = pixels[y : y + resolved_block_height, x : x + block_width]
            result[y : y + resolved_block_height, x : x + block_width, :3] = _average_rgb(
                patch[:, :, :3], average_type
            )
            if patch.shape[2] == 4:
                result[y : y + resolved_block_height, x : x + block_width, 3] = int(
                    patch[:, :, 3].mean()
                )
    output = Image.fromarray(result, "RGBA")
    _save_image(output, output_path)
    return ImageOperationResult(
        operation="image.mosaic.pixelate",
        output_path=str(output_path),
        width=output.width,
        height=output.height,
        input_paths=[str(input_path)],
        output_paths=[str(output_path)],
        count=((image.width + block_width - 1) // block_width)
        * ((image.height + resolved_block_height - 1) // resolved_block_height),
    )


def depixelize_mosaic(
    input_path: Path,
    search_path: Path,
    output_path: Path,
    *,
    block_width: int | None = None,
    block_height: int | None = None,
    tolerance: int = 0,
    average_type: str = "gammacorrected",
    background_color: tuple[int, int, int] | None = None,
) -> MosaicDepixResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if not search_path.is_file():
        raise FileNotFoundError(f"文件不存在：{search_path}")
    if block_width is not None and block_width < 1:
        raise ValueError("马赛克块宽必须大于 0")
    if block_height is not None and block_height < 1:
        raise ValueError("马赛克块高必须大于 0")
    if tolerance < 0:
        raise ValueError("颜色容差不能小于 0")
    if average_type not in {"gammacorrected", "linear"}:
        raise ValueError(f"未知平均颜色类型：{average_type}")
    with Image.open(input_path) as source:
        pixelated = source.convert("RGBA")
    with Image.open(search_path) as source:
        search = source.convert("RGBA")
    pixelated_pixels = np.asarray(pixelated).copy()
    search_pixels = np.asarray(search)
    output_pixels = pixelated_pixels.copy()
    blocks = _mosaic_blocks(
        pixelated_pixels[:, :, :3],
        block_width=block_width,
        block_height=block_height,
        background_color=background_color,
    )
    matches_by_size: dict[tuple[int, int], dict[tuple[int, int, int], list[tuple[int, int]]]] = {}
    matched = 0
    for x, y, width, height, color in blocks:
        size = (width, height)
        if size not in matches_by_size:
            matches_by_size[size] = _search_average_matches(
                search_pixels[:, :, :3], width, height, average_type=average_type
            )
        candidates = _candidate_locations(matches_by_size[size], color, tolerance=tolerance)
        if not candidates:
            continue
        patches = np.stack(
            [search_pixels[cy : cy + height, cx : cx + width] for cx, cy in candidates], axis=0
        )
        if len(candidates) == 1 or np.all(patches == patches[0]):
            replacement = patches[0]
        else:
            replacement = np.rint(patches.astype(np.float32).mean(axis=0)).clip(0, 255).astype(np.uint8)
        output_pixels[y : y + height, x : x + width] = replacement
        matched += 1
    output = Image.fromarray(output_pixels, "RGBA")
    _save_image(output, output_path)
    return MosaicDepixResult(
        operation="image.mosaic.depix",
        output_path=str(output_path),
        width=output.width,
        height=output.height,
        input_paths=[str(input_path), str(search_path)],
        output_paths=[str(output_path)],
        count=matched,
        blocks=len(blocks),
        matched=matched,
        unmatched=len(blocks) - matched,
        average_type=average_type,
    )


def _mosaic_blocks(
    pixels: np.ndarray,
    *,
    block_width: int | None,
    block_height: int | None,
    background_color: tuple[int, int, int] | None,
) -> list[tuple[int, int, int, int, tuple[int, int, int]]]:
    height, width = pixels.shape[:2]
    ignored = {(0, 0, 0), (255, 255, 255)}
    if background_color is not None:
        ignored.add(background_color)
    blocks: list[tuple[int, int, int, int, tuple[int, int, int]]] = []
    if block_width is not None:
        resolved_block_height = block_width if block_height is None else block_height
        for y in range(0, height, resolved_block_height):
            for x in range(0, width, block_width):
                actual_width = min(block_width, width - x)
                actual_height = min(resolved_block_height, height - y)
                color = tuple(int(v) for v in pixels[y, x])
                if color in ignored:
                    continue
                blocks.append((x, y, actual_width, actual_height, color))
        return blocks

    seen = np.zeros((height, width), dtype=bool)
    for y in range(height):
        for x in range(width):
            if seen[y, x]:
                continue
            color_array = pixels[y, x]
            color = tuple(int(v) for v in color_array)
            run_width = 1
            while x + run_width < width and np.array_equal(pixels[y, x + run_width], color_array):
                run_width += 1
            run_height = 1
            while y + run_height < height and np.all(
                pixels[y + run_height, x : x + run_width] == color_array
            ):
                run_height += 1
            seen[y : y + run_height, x : x + run_width] = True
            if color not in ignored:
                blocks.append((x, y, run_width, run_height, color))
    return blocks


def _search_average_matches(
    search_pixels: np.ndarray,
    width: int,
    height: int,
    *,
    average_type: str,
) -> dict[tuple[int, int, int], list[tuple[int, int]]]:
    search_height, search_width = search_pixels.shape[:2]
    if width > search_width or height > search_height:
        return {}
    matches: dict[tuple[int, int, int], list[tuple[int, int]]] = {}
    for y in range(search_height - height + 1):
        for x in range(search_width - width + 1):
            color = _average_rgb(search_pixels[y : y + height, x : x + width], average_type)
            matches.setdefault(color, []).append((x, y))
    return matches


def _candidate_locations(
    matches: dict[tuple[int, int, int], list[tuple[int, int]]],
    color: tuple[int, int, int],
    *,
    tolerance: int,
) -> list[tuple[int, int]]:
    if tolerance == 0:
        return matches.get(color, [])
    candidates: list[tuple[int, int]] = []
    for candidate_color, locations in matches.items():
        if max(abs(candidate_color[channel] - color[channel]) for channel in range(3)) <= tolerance:
            candidates.extend(locations)
    return candidates


def _average_rgb(patch: np.ndarray, average_type: str) -> tuple[int, int, int]:
    values = patch[:, :, :3].astype(np.float64)
    if average_type == "linear":
        normalized = values / 255.0
        linear = np.where(
            normalized <= 0.0404482362771082,
            normalized / 12.92,
            ((normalized + 0.055) / 1.055) ** 2.4,
        )
        mean = linear.mean(axis=(0, 1))
        srgb = np.where(mean > 0.0031308, 1.055 * np.power(mean, 1 / 2.4) - 0.055, 12.92 * mean)
        return tuple(np.rint(srgb.clip(0, 1) * 255).astype(int).tolist())
    mean = values.mean(axis=(0, 1))
    return tuple(int(channel) for channel in mean)


def combine_images(
    first_path: Path,
    second_path: Path,
    output_path: Path,
    *,
    operation: CombineOperation = "xor",
) -> ImageOperationResult:
    missing = next((path for path in (first_path, second_path) if not path.is_file()), None)
    if missing is not None:
        raise FileNotFoundError(f"文件不存在：{missing}")
    if operation not in {*COMBINE_OPERATIONS, "all"}:
        raise ValueError(f"未知图片组合操作：{operation}")
    with Image.open(first_path) as first_source:
        first = np.array(first_source.convert("RGB"), dtype=np.uint32)
    with Image.open(second_path) as second_source:
        second = np.array(second_source.convert("RGB"), dtype=np.uint32)
    if operation == "all":
        output_path.mkdir(parents=True, exist_ok=True)
        outputs = [output_path / f"{index:02d}-{name}.png" for index, name in enumerate(COMBINE_OPERATIONS)]
        results = [_combine_pixels(first, second, name) for name in COMBINE_OPERATIONS]
        for pixels, output in zip(results, outputs, strict=True):
            _save_image(Image.fromarray(pixels, "RGB"), output)
        return ImageOperationResult(
            operation="image.combine.all",
            output_path=str(output_path),
            width=max(result.shape[1] for result in results),
            height=max(result.shape[0] for result in results),
            input_paths=[str(first_path), str(second_path)],
            output_paths=[str(output) for output in outputs],
            count=len(outputs),
        )
    pixels = _combine_pixels(first, second, operation)
    _save_image(Image.fromarray(pixels, "RGB"), output_path)
    return ImageOperationResult(
        operation=f"image.combine.{operation}",
        output_path=str(output_path),
        width=pixels.shape[1],
        height=pixels.shape[0],
        input_paths=[str(first_path), str(second_path)],
        output_paths=[str(output_path)],
        count=2,
    )


def _combine_pixels(
    first: np.ndarray,
    second: np.ndarray,
    operation: str,
) -> np.ndarray:
    if operation in {"interlace-h", "interlace-v"}:
        height = min(first.shape[0], second.shape[0])
        width = min(first.shape[1], second.shape[1])
        if operation == "interlace-h":
            result = np.empty((height * 2, width, 3), dtype=np.uint8)
            result[0::2] = first[:height, :width]
            result[1::2] = second[:height, :width]
            return result
        result = np.empty((height, width * 2, 3), dtype=np.uint8)
        result[:, 0::2] = first[:height, :width]
        result[:, 1::2] = second[:height, :width]
        return result

    height = max(first.shape[0], second.shape[0])
    width = max(first.shape[1], second.shape[1])
    left = np.zeros((height, width, 3), dtype=np.uint32)
    right = np.zeros((height, width, 3), dtype=np.uint32)
    left[: first.shape[0], : first.shape[1]] = first
    right[: second.shape[0], : second.shape[1]] = second
    if operation == "add-rgb":
        return ((left + right) & 0xFF).astype(np.uint8)
    if operation == "sub-rgb":
        return ((left.astype(np.int64) - right) & 0xFF).astype(np.uint8)
    if operation == "mul-rgb":
        return ((left * right) & 0xFF).astype(np.uint8)
    if operation == "lightest":
        return np.maximum(left, right).astype(np.uint8)
    if operation == "darkest":
        return np.minimum(left, right).astype(np.uint8)

    left_packed = (left[:, :, 0] << 16) | (left[:, :, 1] << 8) | left[:, :, 2]
    right_packed = (right[:, :, 0] << 16) | (right[:, :, 1] << 8) | right[:, :, 2]
    if operation == "xor":
        packed = left_packed ^ right_packed
    elif operation == "or":
        packed = left_packed | right_packed
    elif operation == "and":
        packed = left_packed & right_packed
    elif operation == "add":
        packed = (left_packed + right_packed) & 0xFFFFFF
    elif operation == "sub":
        packed = (left_packed.astype(np.int64) - right_packed) & 0xFFFFFF
    else:
        packed = (left_packed.astype(np.uint64) * right_packed) & 0xFFFFFF
    return np.stack(
        ((packed >> 16) & 0xFF, (packed >> 8) & 0xFF, packed & 0xFF),
        axis=2,
    ).astype(np.uint8)


def _natural_key(path: Path) -> list[object]:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", path.name)]


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
