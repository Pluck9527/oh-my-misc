"""Peano and Hilbert space-filling curve image transformations.

CTF challenges sometimes serialize a square image along a recursive curve and
then write that sequence as an ordinary row-major image.  This module provides
the inverse operation as well as the matching encoder for producing fixtures.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import numpy as np
from PIL import Image

Curve = Literal["peano", "hilbert"]
Action = Literal["encode", "decode"]


@dataclass(frozen=True)
class SpaceFillResult:
    operation: str
    output_path: str
    width: int
    height: int
    input_paths: list[str]
    output_paths: list[str]
    count: int
    curve: str
    action: str
    order: int
    side: int
    flip_y: bool
    reverse: bool

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def transform_spacefill_image(
    input_path: Path,
    output_path: Path,
    *,
    curve: Curve | str,
    action: Action | str,
    order: int | None = None,
    flip_y: bool = True,
    reverse: bool = False,
) -> SpaceFillResult:
    """Encode or decode an image using Peano/Hilbert traversal order.

    ``decode`` reads the input in row-major order and writes those pixels onto
    the curve.  ``encode`` performs the exact inverse.  ``flip_y=True`` matches
    the ``height - 1 - y`` convention used by the guide's Peano script.
    """
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if curve not in {"peano", "hilbert"}:
        raise ValueError(f"未知填满空间曲线：{curve}")
    if action not in {"encode", "decode"}:
        raise ValueError(f"未知填满空间曲线操作：{action}")

    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    if image.width != image.height:
        raise ValueError("填满空间曲线图像必须是正方形")

    resolved_order = infer_spacefill_order(curve, image.width) if order is None else order
    if resolved_order < 0:
        raise ValueError("曲线阶数不能小于 0")
    side = (3 if curve == "peano" else 2) ** resolved_order
    if side != image.width:
        raise ValueError(f"曲线阶数 {resolved_order} 对应边长 {side}，但图片边长为 {image.width}")

    points = spacefill_points(curve, resolved_order)
    if reverse:
        points.reverse()
    coordinates = np.asarray(points, dtype=np.int64)
    x_coordinates = coordinates[:, 0]
    y_coordinates = coordinates[:, 1]
    if flip_y:
        y_coordinates = side - 1 - y_coordinates

    pixels = np.asarray(image)
    if action == "decode":
        result = np.empty_like(pixels)
        result[y_coordinates, x_coordinates] = pixels.reshape(-1, pixels.shape[2])
    else:
        result = pixels[y_coordinates, x_coordinates].reshape(pixels.shape)

    output = Image.fromarray(result, "RGBA")
    _save_image(output, output_path)
    return SpaceFillResult(
        operation=f"image.spacefill.{action}",
        output_path=str(output_path),
        width=output.width,
        height=output.height,
        input_paths=[str(input_path)],
        output_paths=[str(output_path)],
        count=len(points),
        curve=curve,
        action=action,
        order=resolved_order,
        side=side,
        flip_y=flip_y,
        reverse=reverse,
    )


def infer_spacefill_order(curve: Curve | str, side: int) -> int:
    """Infer ``n`` for a side length of ``3**n`` or ``2**n``."""
    if curve not in {"peano", "hilbert"}:
        raise ValueError(f"未知填满空间曲线：{curve}")
    if side < 1:
        raise ValueError("图片边长必须大于 0")
    base = 3 if curve == "peano" else 2
    order = 0
    value = 1
    while value < side:
        value *= base
        order += 1
    if value != side:
        raise ValueError(f"边长 {side} 不是 {curve} 曲线要求的 {base}^n")
    return order


def spacefill_points(curve: Curve | str, order: int) -> list[tuple[int, int]]:
    """Return every grid coordinate in traversal order."""
    if curve not in {"peano", "hilbert"}:
        raise ValueError(f"未知填满空间曲线：{curve}")
    if order < 0:
        raise ValueError("曲线阶数不能小于 0")
    return peano_points(order) if curve == "peano" else hilbert_points(order)


def peano_points(order: int) -> list[tuple[int, int]]:
    """Generate the same recursive 3×3 Peano traversal as the guide."""
    if order < 0:
        raise ValueError("曲线阶数不能小于 0")
    if order == 0:
        return [(0, 0)]
    inner = peano_points(order - 1)
    points = inner.copy()
    px, py = points[-1]
    points.extend((px - x, py + 1 + y) for x, y in inner)
    px, py = points[-1]
    points.extend((px + x, py + 1 + y) for x, y in inner)
    px, py = points[-1]
    points.extend((px + 1 + x, py - y) for x, y in inner)
    px, py = points[-1]
    points.extend((px - x, py - 1 - y) for x, y in inner)
    px, py = points[-1]
    points.extend((px + x, py - 1 - y) for x, y in inner)
    px, py = points[-1]
    points.extend((px + 1 + x, py + y) for x, y in inner)
    px, py = points[-1]
    points.extend((px - x, py + 1 + y) for x, y in inner)
    px, py = points[-1]
    points.extend((px + x, py + 1 + y) for x, y in inner)
    return points


def hilbert_points(order: int) -> list[tuple[int, int]]:
    """Generate a standard 2×2 recursive Hilbert traversal."""
    if order < 0:
        raise ValueError("曲线阶数不能小于 0")
    side = 1 << order
    return [_hilbert_distance_to_xy(side, distance) for distance in range(side * side)]


def _hilbert_distance_to_xy(side: int, distance: int) -> tuple[int, int]:
    x = y = 0
    scale = 1
    remaining = distance
    while scale < side:
        rx = 1 & (remaining // 2)
        ry = 1 & (remaining ^ rx)
        x, y = _hilbert_rotate(scale, x, y, rx, ry)
        x += scale * rx
        y += scale * ry
        remaining //= 4
        scale *= 2
    return x, y


def _hilbert_rotate(scale: int, x: int, y: int, rx: int, ry: int) -> tuple[int, int]:
    if ry == 0:
        if rx == 1:
            x = scale - 1 - x
            y = scale - 1 - y
        return y, x
    return x, y


def _save_image(image: Image.Image, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.suffix.lower() in {".jpg", ".jpeg"}:
        image.convert("RGB").save(output_path, quality=95)
    else:
        image.save(output_path)
