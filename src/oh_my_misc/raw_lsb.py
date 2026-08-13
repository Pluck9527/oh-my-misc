from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

_MAGIC_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("zip", b"PK\x03\x04"),
    ("zip-empty", b"PK\x05\x06"),
    ("zip-spanned", b"PK\x07\x08"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("pdf", b"%PDF-"),
    ("gif87a", b"GIF87a"),
    ("gif89a", b"GIF89a"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("gzip", b"\x1f\x8b\x08"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("sqlite", b"SQLite format 3\x00"),
    ("elf", b"\x7fELF"),
    ("bmp", b"BM"),
)


@dataclass(frozen=True)
class RawLsbResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    tool_path: str
    width: int
    height: int
    source: str
    bit: int | None
    order: str | None
    crop: tuple[int, int, int, int] | None
    offset: int
    limit: int | None
    written_bytes: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def extract_raw_lsb(
    input_path: Path,
    output_path: Path,
    *,
    bit: int = 0,
    order: str = "msb",
    source: str = "visible",
    crop: tuple[int, int, int, int] | None = None,
    offset: int = 0,
    limit: int | None = None,
) -> RawLsbResult:
    """Extract bytes from one LSB bit plane of a camera RAW Bayer array."""

    _check_file(input_path, "RAW 文件")
    _validate_bit(bit)
    _validate_order(order)
    _validate_slice(offset, limit)
    plane = _load_raw_plane(input_path, source=source)
    view = _crop_plane(plane, crop)
    payload = _apply_byte_window(_bits_to_bytes(view, bit=bit, order=order), offset, limit)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    height, width = view.shape[:2]
    findings = _find_magic(payload, search_window=min(len(payload), 4096))
    return RawLsbResult(
        operation="image.raw-lsb.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="rawpy",
        width=width,
        height=height,
        source=source,
        bit=bit,
        order=order,
        crop=crop,
        offset=offset,
        limit=limit,
        written_bytes=len(payload),
        findings=findings,
    )


def scan_raw_lsb(
    input_path: Path,
    output_dir: Path,
    *,
    bits: Iterable[int] = range(4),
    orders: Sequence[str] = ("msb", "lsb"),
    source: str = "visible",
    crop: tuple[int, int, int, int] | None = None,
    max_bytes: int = 1_048_576,
    search_window: int = 4096,
    write_all: bool = False,
) -> RawLsbResult:
    """Scan RAW LSB bit planes and write streams that look like embedded files."""

    _check_file(input_path, "RAW 文件")
    bit_list = list(bits)
    if not bit_list:
        raise ValueError("bits 不能为空")
    for bit in bit_list:
        _validate_bit(bit)
    order_list = list(orders)
    if not order_list:
        raise ValueError("orders 不能为空")
    for order in order_list:
        _validate_order(order)
    if max_bytes <= 0:
        raise ValueError("max_bytes 必须大于 0")
    if search_window <= 0:
        raise ValueError("search_window 必须大于 0")
    plane = _load_raw_plane(input_path, source=source)
    view = _crop_plane(plane, crop)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_paths: list[str] = []
    findings: list[dict[str, Any]] = []
    for bit in bit_list:
        for order in order_list:
            stream = _bits_to_bytes(view, bit=bit, order=order, max_bytes=max_bytes)
            matches = _find_magic(stream, search_window=min(search_window, len(stream)))
            if write_all or matches:
                if matches:
                    for index, match in enumerate(matches):
                        start = int(match["offset"])
                        name = f"bit{bit}-{order}-off{start}-{match['kind']}-{index}.bin"
                        candidate = output_dir / name
                        candidate.write_bytes(stream[start:])
                        enriched = dict(match)
                        enriched.update({"bit": bit, "order": order, "output_path": str(candidate)})
                        findings.append(enriched)
                        output_paths.append(str(candidate))
                else:
                    candidate = output_dir / f"bit{bit}-{order}.bin"
                    candidate.write_bytes(stream)
                    output_paths.append(str(candidate))
    height, width = view.shape[:2]
    manifest = output_dir / "manifest.json"
    manifest_payload = {
        "status": "success",
        "operation": "image.raw-lsb.scan",
        "input_path": str(input_path),
        "width": width,
        "height": height,
        "source": source,
        "crop": crop,
        "bits": bit_list,
        "orders": order_list,
        "max_bytes": max_bytes,
        "search_window": search_window,
        "write_all": write_all,
        "findings": findings,
        "output_paths": [str(manifest), *output_paths],
    }
    manifest.write_text(json.dumps(manifest_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    output_paths.insert(0, str(manifest))
    return RawLsbResult(
        operation="image.raw-lsb.scan",
        input_path=str(input_path),
        output_path=str(manifest),
        output_paths=output_paths,
        tool_path="rawpy",
        width=width,
        height=height,
        source=source,
        bit=None,
        order=None,
        crop=crop,
        offset=0,
        limit=max_bytes,
        written_bytes=sum(Path(path).stat().st_size for path in output_paths if Path(path).exists()),
        findings=findings,
        count=len(output_paths),
    )


def _load_raw_plane(input_path: Path, *, source: str) -> np.ndarray:
    attribute = {"visible": "raw_image_visible", "full": "raw_image"}.get(source)
    if attribute is None:
        raise ValueError("source 必须是 visible 或 full")
    try:
        import rawpy  # type: ignore[import-not-found]
    except ModuleNotFoundError as error:
        raise ValueError("RAW LSB 需要安装 rawpy：pip install -e '.[raw]'") from error
    with rawpy.imread(str(input_path)) as raw:
        plane = getattr(raw, attribute, None)
        if plane is None:
            raise ValueError(f"rawpy 对象缺少 {attribute}")
        array = np.asarray(plane)
        if array.ndim != 2:
            raise ValueError(f"{attribute} 应为二维 Bayer 阵列，当前维度为 {array.ndim}")
        return array.copy()


def _crop_plane(plane: np.ndarray, crop: tuple[int, int, int, int] | None) -> np.ndarray:
    if crop is None:
        return plane
    x, y, width, height = crop
    if x < 0 or y < 0 or width <= 0 or height <= 0:
        raise ValueError("crop 必须为非负 X,Y 和正 W,H")
    if y + height > plane.shape[0] or x + width > plane.shape[1]:
        raise ValueError(
            f"crop 超出 RAW 尺寸：crop={crop}，尺寸={plane.shape[1]}x{plane.shape[0]}"
        )
    return plane[y : y + height, x : x + width]


def _bits_to_bytes(
    plane: np.ndarray,
    *,
    bit: int,
    order: str,
    max_bytes: int | None = None,
) -> bytes:
    values = np.ravel(plane)
    byte_count = len(values) // 8
    if max_bytes is not None:
        byte_count = min(byte_count, max_bytes)
    if byte_count <= 0:
        return b""
    bits = ((values[: byte_count * 8] >> bit) & 1).astype(np.uint8, copy=False)
    grouped = bits.reshape(byte_count, 8)
    weights = (
        np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint8)
        if order == "msb"
        else np.array([1, 2, 4, 8, 16, 32, 64, 128], dtype=np.uint8)
    )
    return np.sum(grouped * weights, axis=1, dtype=np.uint16).astype(np.uint8).tobytes()


def _apply_byte_window(data: bytes, offset: int, limit: int | None) -> bytes:
    if offset:
        data = data[offset:]
    if limit is not None:
        data = data[:limit]
    return data


def _find_magic(data: bytes, *, search_window: int) -> list[dict[str, Any]]:
    haystack = data[:search_window]
    findings: list[dict[str, Any]] = []
    for kind, signature in _MAGIC_SIGNATURES:
        start = haystack.find(signature)
        if start >= 0:
            findings.append(
                {
                    "kind": kind,
                    "offset": start,
                    "signature_hex": signature.hex(),
                    "preview_hex": data[start : start + 32].hex(),
                }
            )
    findings.sort(key=lambda item: (int(item["offset"]), str(item["kind"])))
    return findings


def _validate_bit(bit: int) -> None:
    if bit < 0 or bit > 31:
        raise ValueError("bit 必须在 0..31")


def _validate_order(order: str) -> None:
    if order not in {"msb", "lsb"}:
        raise ValueError("order 必须是 msb 或 lsb")


def _validate_slice(offset: int, limit: int | None) -> None:
    if offset < 0:
        raise ValueError("offset 必须大于等于 0")
    if limit is not None and limit < 0:
        raise ValueError("limit 必须大于等于 0")


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
