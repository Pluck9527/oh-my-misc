from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

import numpy as np
from PIL import Image, ImageDraw, ImageFont

WatermarkScheme = Literal["best", "high", "low", "pad", "partial"]
DualWatermarkVariant = Literal["chishaxie", "linyacool"]
Ww23Transform = Literal["dct", "dft"]


@dataclass(frozen=True)
class WatermarkResult:
    operation: Literal[
        "watermark.single.embed",
        "watermark.single.extract",
        "watermark.dual.embed",
        "watermark.dual.extract",
        "watermark.ww23.embed",
        "watermark.ww23.extract",
    ]
    input_path: str
    output_path: str
    width: int
    height: int
    work_width: int
    work_height: int
    scheme: WatermarkScheme
    watermark_path: str | None = None
    reference_path: str | None = None
    variant: DualWatermarkVariant | None = None
    seed: int | None = None
    alpha: float | None = None
    transform: Ww23Transform | None = None

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def embed_single_watermark(
    input_path: Path,
    output_path: Path,
    text: str,
    *,
    strength: float = 20,
    scheme: WatermarkScheme = "best",
    font_path: Path | None = None,
    font_size: int = 32,
) -> WatermarkResult:
    if not text:
        raise ValueError("水印文字不能为空")
    if strength < 0:
        raise ValueError("水印强度不能小于 0")
    if font_size < 1:
        raise ValueError("字体大小必须大于 0")

    source = _open_rgba(input_path)
    work = _prepare_embed(source, scheme)
    watermark = _render_symmetric_text(
        work.size,
        text,
        _load_font(font_path, font_size),
    )
    embedded = _embed_fft(work, watermark, strength)
    result = _finish_embed(source, embedded, scheme)
    _save_image(result, output_path)
    return WatermarkResult(
        operation="watermark.single.embed",
        input_path=str(input_path),
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        work_width=work.width,
        work_height=work.height,
        scheme=scheme,
    )


def extract_single_watermark(
    input_path: Path,
    output_path: Path,
    *,
    brightness: float = 5,
    scheme: WatermarkScheme = "best",
) -> WatermarkResult:
    if brightness < 0:
        raise ValueError("提取亮度不能小于 0")

    source = _open_rgba(input_path)
    work = _prepare_extract(source, scheme)
    extracted = _extract_fft(work, brightness)
    result = extracted.resize(source.size, Image.Resampling.BICUBIC)
    _save_image(result, output_path)
    return WatermarkResult(
        operation="watermark.single.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        work_width=work.width,
        work_height=work.height,
        scheme=scheme,
    )


def embed_dual_watermark(
    input_path: Path,
    watermark_path: Path,
    output_path: Path,
    *,
    variant: DualWatermarkVariant = "chishaxie",
    seed: int | None = None,
    alpha: float | None = None,
) -> WatermarkResult:
    carrier = _open_rgb(input_path)
    watermark = _open_rgb(watermark_path)
    resolved_seed, resolved_alpha = _dual_parameters(
        variant,
        carrier.size,
        seed,
        alpha,
    )
    if watermark.height >= carrier.height // 2 or watermark.width >= carrier.width:
        raise ValueError(
            f"水印尺寸必须小于 {carrier.width} × {carrier.height // 2}"
        )

    carrier_pixels = np.array(carrier, dtype=np.float64)
    watermark_pixels = np.array(watermark, dtype=np.float64)
    rows, columns = _shuffle_indices(
        carrier.height // 2,
        carrier.width,
        resolved_seed,
    )
    padded = np.zeros_like(carrier_pixels)
    padded[: watermark.height, : watermark.width] = watermark_pixels
    shuffled = padded[: carrier.height // 2][np.ix_(rows, columns)]
    frequency_mark = np.zeros_like(carrier_pixels)
    frequency_mark[: carrier.height // 2] = shuffled
    frequency_mark[-1 : -(carrier.height // 2) - 1 : -1, ::-1] = shuffled
    spectrum = np.fft.fft2(carrier_pixels, axes=(0, 1))
    embedded = np.real(
        np.fft.ifft2(
            spectrum + resolved_alpha * frequency_mark,
            axes=(0, 1),
        )
    )
    result = Image.fromarray(np.clip(np.rint(embedded), 0, 255).astype(np.uint8), "RGB")
    _save_image(result, output_path)
    return WatermarkResult(
        operation="watermark.dual.embed",
        input_path=str(input_path),
        watermark_path=str(watermark_path),
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        work_width=result.width,
        work_height=result.height,
        scheme="best",
        variant=variant,
        seed=resolved_seed,
        alpha=resolved_alpha,
    )


def extract_dual_watermark(
    reference_path: Path,
    input_path: Path,
    output_path: Path,
    *,
    variant: DualWatermarkVariant = "chishaxie",
    seed: int | None = None,
    alpha: float | None = None,
    crop: bool = True,
    watermark_size: tuple[int, int] | None = None,
) -> WatermarkResult:
    reference = _open_rgb(reference_path)
    embedded = _open_rgb(input_path)
    if reference.size != embedded.size:
        raise ValueError(
            "原图与含水印图尺寸必须一致："
            f"{reference.width} × {reference.height} != "
            f"{embedded.width} × {embedded.height}"
        )
    resolved_seed, resolved_alpha = _dual_parameters(
        variant,
        reference.size,
        seed,
        alpha,
    )
    rows, columns = _shuffle_indices(
        reference.height // 2,
        reference.width,
        resolved_seed,
    )
    reference_spectrum = np.fft.fft2(
        np.array(reference, dtype=np.float64),
        axes=(0, 1),
    )
    embedded_spectrum = np.fft.fft2(
        np.array(embedded, dtype=np.float64),
        axes=(0, 1),
    )
    recovered = np.real(
        (embedded_spectrum - reference_spectrum) / resolved_alpha
    )
    watermark = np.zeros_like(recovered)
    watermark[np.ix_(rows, columns)] = recovered[: reference.height // 2]
    watermark = np.clip(np.rint(watermark), 0, 255).astype(np.uint8)
    if watermark_size is not None:
        width, height = watermark_size
        if width < 1 or height < 1:
            raise ValueError("水印尺寸必须大于 0")
        if width >= reference.width or height >= reference.height // 2:
            raise ValueError(
                f"水印尺寸必须小于 {reference.width} × {reference.height // 2}"
            )
        watermark = watermark[:height, :width]
    elif crop:
        watermark = _crop_nonzero(watermark[: reference.height // 2])
    result = Image.fromarray(watermark, "RGB")
    _save_image(result, output_path)
    return WatermarkResult(
        operation="watermark.dual.extract",
        input_path=str(input_path),
        reference_path=str(reference_path),
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        work_width=reference.width,
        work_height=reference.height,
        scheme="best",
        variant=variant,
        seed=resolved_seed,
        alpha=resolved_alpha,
    )


def embed_ww23_watermark(
    input_path: Path,
    watermark_path: Path,
    output_path: Path,
    *,
    transform: Ww23Transform = "dct",
    alpha: float | None = None,
) -> WatermarkResult:
    carrier = _open_rgb(input_path)
    watermark = _open_grayscale(watermark_path)
    resolved_alpha = _ww23_alpha(transform, alpha)
    carrier_pixels = np.array(carrier, dtype=np.float64)
    watermark_pixels = np.array(watermark, dtype=np.float64)
    if transform == "dct":
        work_height = carrier.height + carrier.height % 2
        work_width = carrier.width + carrier.width % 2
        if watermark.height > work_height or watermark.width > work_width:
            raise ValueError(f"水印尺寸不能超过 {work_width} × {work_height}")
        work = np.zeros((work_height, work_width, 3), dtype=np.float64)
        work[: carrier.height, : carrier.width] = carrier_pixels
        embedded = np.empty_like(work)
        centered = np.where(watermark_pixels == 0, 2, watermark_pixels)
        row = (work_height - watermark.height) // 2
        column = (work_width - watermark.width) // 2
        mark = np.zeros((work_height, work_width), dtype=np.float64)
        mark[row : row + watermark.height, column : column + watermark.width] = centered
        for channel in range(3):
            coefficients = _dct2(work[:, :, channel])
            embedded[:, :, channel] = _idct2(
                coefficients + resolved_alpha * mark
            )
        result_pixels = embedded[: carrier.height, : carrier.width]
    else:
        if watermark.height >= carrier.height // 2 or watermark.width > carrier.width:
            raise ValueError(
                f"水印尺寸必须小于或等于 {carrier.width} × {carrier.height // 2 - 1}"
            )
        top = np.pad(
            watermark_pixels,
            (
                (
                    (carrier.height // 2 - watermark.height) // 2,
                    carrier.height
                    // 2
                    - watermark.height
                    - (carrier.height // 2 - watermark.height) // 2,
                ),
                (
                    (carrier.width - watermark.width) // 2,
                    carrier.width
                    - watermark.width
                    - (carrier.width - watermark.width) // 2,
                ),
            ),
        )
        mark = np.concatenate((top, np.flip(top, axis=(0, 1))), axis=0)
        if mark.shape[0] < carrier.height:
            mark = np.pad(mark, ((0, carrier.height - mark.shape[0]), (0, 0)))
        embedded_channels = [
            _normalize_u8(
                np.real(
                    np.fft.ifft2(
                        np.fft.fft2(carrier_pixels[:, :, channel])
                        + resolved_alpha * (mark + 1j * mark)
                    )
                )
            )
            for channel in range(3)
        ]
        result_pixels = np.stack(embedded_channels, axis=2)
        work_width, work_height = carrier.size
    result = Image.fromarray(
        np.clip(np.rint(result_pixels), 0, 255).astype(np.uint8),
        "RGB",
    )
    _save_image(result, output_path)
    return WatermarkResult(
        operation="watermark.ww23.embed",
        input_path=str(input_path),
        watermark_path=str(watermark_path),
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        work_width=work_width,
        work_height=work_height,
        scheme="best",
        alpha=resolved_alpha,
        transform=transform,
    )


def extract_ww23_watermark(
    input_path: Path,
    output_path: Path,
    *,
    transform: Ww23Transform = "dct",
) -> WatermarkResult:
    source = _open_grayscale(input_path)
    pixels = np.array(source, dtype=np.float64)
    if transform == "dct":
        work_height = source.height + source.height % 2
        work_width = source.width + source.width % 2
        work = np.zeros((work_height, work_width), dtype=np.float64)
        work[: source.height, : source.width] = pixels
        spectrum = _dct2(work)
        visible = np.where((spectrum >= 0) & (spectrum <= 16), 255, 0).astype(
            np.uint8
        )
    else:
        spectrum = np.fft.fft2(pixels)
        magnitude = np.log1p(np.abs(spectrum))
        visible = _normalize_u8(magnitude)
        work_width, work_height = source.size
    result = Image.fromarray(visible, "L")
    _save_image(result, output_path)
    return WatermarkResult(
        operation="watermark.ww23.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        width=result.width,
        height=result.height,
        work_width=work_width,
        work_height=work_height,
        scheme="best",
        transform=transform,
    )


def _open_rgba(path: Path) -> Image.Image:
    if not path.is_file():
        raise FileNotFoundError(f"文件不存在：{path}")
    with Image.open(path) as image:
        return image.convert("RGBA")


def _open_rgb(path: Path) -> Image.Image:
    if not path.is_file():
        raise FileNotFoundError(f"文件不存在：{path}")
    with Image.open(path) as image:
        return image.convert("RGB")


def _open_grayscale(path: Path) -> Image.Image:
    if not path.is_file():
        raise FileNotFoundError(f"文件不存在：{path}")
    with Image.open(path) as image:
        return image.convert("L")


def _ww23_alpha(transform: Ww23Transform, alpha: float | None) -> float:
    if transform not in {"dct", "dft"}:
        raise ValueError(f"未知 ww23 变换：{transform}")
    resolved = alpha if alpha is not None else (0.03 if transform == "dct" else 8.0)
    if resolved <= 0:
        raise ValueError("水印强度必须大于 0")
    return resolved


def _dct2(pixels: np.ndarray) -> np.ndarray:
    return _dct1(_dct1(pixels).T).T


def _idct2(coefficients: np.ndarray) -> np.ndarray:
    return _idct1(_idct1(coefficients).T).T


def _dct1(pixels: np.ndarray) -> np.ndarray:
    size = pixels.shape[0]
    indexes = np.arange(size, dtype=np.float64)
    basis = np.cos(np.pi / size * (indexes[:, None] + 0.5) * indexes[None, :])
    basis[:, 0] /= np.sqrt(2)
    return np.sqrt(2 / size) * basis.T @ pixels


def _idct1(coefficients: np.ndarray) -> np.ndarray:
    size = coefficients.shape[0]
    indexes = np.arange(size, dtype=np.float64)
    basis = np.cos(np.pi / size * (indexes[:, None] + 0.5) * indexes[None, :])
    basis[:, 0] /= np.sqrt(2)
    return np.sqrt(2 / size) * basis @ coefficients


def _normalize_u8(pixels: np.ndarray) -> np.ndarray:
    minimum = float(pixels.min())
    maximum = float(pixels.max())
    if maximum == minimum:
        return np.zeros(pixels.shape, dtype=np.uint8)
    return np.rint((pixels - minimum) * 255 / (maximum - minimum)).astype(np.uint8)


def _dual_parameters(
    variant: DualWatermarkVariant,
    size: tuple[int, int],
    seed: int | None,
    alpha: float | None,
) -> tuple[int, float]:
    if variant not in {"chishaxie", "linyacool"}:
        raise ValueError(f"未知双图水印变体：{variant}")
    resolved_seed = seed if seed is not None else (
        20160930 if variant == "chishaxie" else size[0] + size[1]
    )
    resolved_alpha = alpha if alpha is not None else (
        3.0 if variant == "chishaxie" else 5.0
    )
    if resolved_alpha <= 0:
        raise ValueError("水印强度必须大于 0")
    return resolved_seed, resolved_alpha


def _shuffle_indices(
    height: int,
    width: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    generator = random.Random(seed)
    rows = list(range(height))
    columns = list(range(width))
    generator.shuffle(rows)
    generator.shuffle(columns)
    return np.array(rows), np.array(columns)


def _crop_nonzero(pixels: np.ndarray) -> np.ndarray:
    occupied = np.any(pixels != 0, axis=2)
    rows = np.flatnonzero(np.any(occupied, axis=1))
    columns = np.flatnonzero(np.any(occupied, axis=0))
    if len(rows) == 0 or len(columns) == 0:
        return pixels
    return pixels[rows[0] : rows[-1] + 1, columns[0] : columns[-1] + 1]


def _nearest_power(value: int) -> int:
    return 2 ** round(np.log2(value))


def _ceil_power(value: int) -> int:
    return 2 ** int(np.ceil(np.log2(value)))


def _floor_power(value: int) -> int:
    return 2 ** int(np.floor(np.log2(value)))


def _power_size(image: Image.Image, mode: Literal["nearest", "ceil", "floor"]) -> tuple[int, int]:
    operation = {"nearest": _nearest_power, "ceil": _ceil_power, "floor": _floor_power}[mode]
    return operation(image.width), operation(image.height)


def _prepare_embed(source: Image.Image, scheme: WatermarkScheme) -> Image.Image:
    if scheme in {"best", "high"}:
        return source.resize(_power_size(source, "nearest"), Image.Resampling.BICUBIC)
    if scheme == "low":
        return source.resize(_power_size(source, "nearest"), Image.Resampling.NEAREST)
    if scheme == "pad":
        canvas = Image.new("RGBA", _power_size(source, "ceil"), (255, 255, 255, 255))
        canvas.paste(source, (0, 0))
        return canvas
    if scheme == "partial":
        width, height = _power_size(source, "floor")
        return source.crop((0, 0, width, height))
    raise ValueError(f"未知转换方案：{scheme}")


def _finish_embed(
    source: Image.Image,
    embedded: Image.Image,
    scheme: WatermarkScheme,
) -> Image.Image:
    if scheme == "best":
        return embedded
    if scheme == "high":
        return embedded.resize(source.size, Image.Resampling.BICUBIC)
    if scheme == "low":
        return embedded.resize(source.size, Image.Resampling.NEAREST)
    if scheme == "pad":
        return embedded.crop((0, 0, source.width, source.height))
    if scheme == "partial":
        result = source.copy()
        result.paste(embedded, (0, 0))
        return result
    raise ValueError(f"未知转换方案：{scheme}")


def _prepare_extract(source: Image.Image, scheme: WatermarkScheme) -> Image.Image:
    if scheme in {"best", "high", "low"}:
        return source.resize(_power_size(source, "nearest"), Image.Resampling.BICUBIC)
    if scheme == "pad":
        canvas = Image.new("RGBA", _power_size(source, "ceil"), (0, 0, 0, 255))
        canvas.paste(source, (0, 0))
        return canvas
    if scheme == "partial":
        width, height = _power_size(source, "floor")
        return source.crop((0, 0, width, height))
    raise ValueError(f"未知转换方案：{scheme}")


def _load_font(path: Path | None, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    if path is not None:
        return ImageFont.truetype(str(path), size)

    candidates = (
        Path("C:/Windows/Fonts/simhei.ttf"),
        Path("C:/Windows/Fonts/msyh.ttc"),
        Path("/System/Library/Fonts/PingFang.ttc"),
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
        Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    )
    selected = next((candidate for candidate in candidates if candidate.is_file()), None)
    if selected is not None:
        return ImageFont.truetype(str(selected), size)
    return ImageFont.load_default(size=size)


def _render_symmetric_text(
    size: tuple[int, int],
    text: str,
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> Image.Image:
    image = Image.new("RGB", size, "black")
    draw = ImageDraw.Draw(image)
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    width = right - left
    height = bottom - top
    position = (size[0] / 2 - width / 2 - left, size[1] / 2 - height - top)
    draw.text(position, text, font=font, fill="white")

    pixels = np.array(image, dtype=np.uint8)
    flat = pixels.reshape(-1, 3)
    half = len(flat) // 2
    flat[-half:] = flat[:half][::-1]
    return Image.fromarray(pixels, "RGB")


def _embed_fft(source: Image.Image, watermark: Image.Image, strength: float) -> Image.Image:
    pixels = np.array(source, dtype=np.uint8)
    channels = pixels[:, :, :3].astype(np.float32) / 256.0
    mark = np.array(watermark, dtype=np.uint8).astype(np.float32) / 256.0
    spectrum = np.fft.fft2(channels, axes=(0, 1), norm="ortho").astype(np.complex64)
    spectrum += mark * np.float32(strength / 500.0)
    restored = np.fft.ifft2(spectrum, axes=(0, 1), norm="ortho").astype(np.complex64)
    pixels[:, :, :3] = np.clip(np.abs(restored) * 256.0, 0, 255).astype(np.uint8)
    return Image.fromarray(pixels, "RGBA")


def _extract_fft(source: Image.Image, brightness: float) -> Image.Image:
    pixels = np.array(source, dtype=np.uint8)
    channels = pixels[:, :, :3].astype(np.float32) / 256.0
    spectrum = np.fft.fft2(channels, axes=(0, 1), norm="ortho").astype(np.complex64)
    extracted = np.clip(np.abs(spectrum) * 256.0 * (brightness / 5.0), 0, 255).astype(
        np.uint8
    )
    pixels[:, :, :3] = extracted
    return Image.fromarray(pixels, "RGBA")


def _save_image(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix in {".jpg", ".jpeg"}:
        image.convert("RGB").save(path, quality=100)
        return
    if suffix == ".bmp":
        image.convert("RGB").save(path)
        return
    if suffix == ".png":
        image.save(path)
        return
    raise ValueError("输出格式仅支持 PNG、JPEG 和 BMP")
