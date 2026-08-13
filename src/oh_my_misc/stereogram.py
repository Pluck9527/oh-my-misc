from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
from PIL import Image


@dataclass(frozen=True)
class StereogramResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    manifest_path: str | None
    width: int
    height: int
    offset: int | None
    offset_start: int
    offset_stop: int
    invert: bool
    count: int

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def solve_stereogram(
    input_path: Path,
    output_path: Path,
    *,
    offset: int | None = None,
    offset_start: int = 1,
    offset_stop: int | None = None,
    invert: bool = False,
    manifest_path: Path | None = None,
) -> StereogramResult:
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    with Image.open(input_path) as source:
        pixels = np.asarray(source.convert("RGB"), dtype=np.uint8)
    width = pixels.shape[1]
    if offset is not None:
        if not 0 <= offset < width:
            raise ValueError(f"偏移量必须在 0..{width - 1} 范围内")
        output = _stegsolve_transform(pixels, offset, invert=invert)
        _save_image(output, output_path)
        return StereogramResult(
            operation="image.stereogram.solve",
            input_path=str(input_path),
            output_path=str(output_path),
            output_paths=[str(output_path)],
            manifest_path=None,
            width=width,
            height=pixels.shape[0],
            offset=offset,
            offset_start=offset,
            offset_stop=offset + 1,
            invert=invert,
            count=1,
        )

    resolved_stop = min(width, offset_stop if offset_stop is not None else width)
    if offset_start < 0 or resolved_stop <= offset_start:
        raise ValueError("偏移范围必须满足 0 <= START < STOP <= 图片宽度")
    output_path.mkdir(parents=True, exist_ok=True)
    digits = max(3, len(str(resolved_stop - 1)))
    outputs = [
        output_path / f"offset-{current:0{digits}d}.png"
        for current in range(offset_start, resolved_stop)
    ]
    for current, output in zip(range(offset_start, resolved_stop), outputs, strict=True):
        _save_image(_stegsolve_transform(pixels, current, invert=invert), output)
    resolved_manifest = manifest_path or output_path / "manifest.json"
    resolved_manifest.parent.mkdir(parents=True, exist_ok=True)
    resolved_manifest.write_text(
        json.dumps(
            {
                "status": "success",
                "operation": "image.stereogram.scan",
                "input_path": str(input_path),
                "offset_start": offset_start,
                "offset_stop": resolved_stop,
                "invert": invert,
                "outputs": [
                    {"offset": current, "output_path": str(output)}
                    for current, output in zip(
                        range(offset_start, resolved_stop), outputs, strict=True
                    )
                ],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return StereogramResult(
        operation="image.stereogram.scan",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output) for output in outputs],
        manifest_path=str(resolved_manifest),
        width=width,
        height=pixels.shape[0],
        offset=None,
        offset_start=offset_start,
        offset_stop=resolved_stop,
        invert=invert,
        count=len(outputs),
    )


def _stegsolve_transform(pixels: np.ndarray, offset: int, *, invert: bool) -> np.ndarray:
    shifted = np.roll(pixels, -offset, axis=1)
    result = np.bitwise_xor(pixels, shifted)
    return np.bitwise_xor(result, 0xFF) if invert else result


def _save_image(pixels: np.ndarray, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.fromarray(pixels, "RGB")
    if path.suffix.lower() in {".jpg", ".jpeg"}:
        image.save(path, quality=100)
        return
    if path.suffix.lower() in {".png", ".bmp"}:
        image.save(path)
        return
    raise ValueError("输出格式仅支持 PNG、JPEG 和 BMP")
