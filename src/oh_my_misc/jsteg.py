from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from oh_my_misc.jphs import JPEG_ZIGZAG, _read_jpeg_dct_image, _write_jpeg_dct_image

_JSTEG_MAGIC = b"jsteg"
_JSTEG_HEADER_SIZE = 9


@dataclass(frozen=True)
class JstegResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    tool_path: str
    width: int
    height: int
    capacity_bytes: int
    payload_bytes: int
    written_bytes: int
    raw: bool = False
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def reveal_jsteg(input_path: Path, output_path: Path, *, raw: bool = False) -> JstegResult:
    """Extract a jsteg payload from a baseline JPEG DCT coefficient stream."""

    _check_file(input_path, "JPEG 文件")
    image = _read_jpeg_dct_image(input_path)
    stream = _read_lsb_stream(image)
    capacity = _jsteg_capacity_bytes(image)
    payload = stream if raw else _parse_jsteg_payload(stream)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return JstegResult(
        operation="image.jsteg.reveal",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        width=image.width,
        height=image.height,
        capacity_bytes=capacity,
        payload_bytes=len(payload),
        written_bytes=len(payload),
        raw=raw,
    )


def hide_jsteg(
    input_path: Path,
    output_path: Path,
    *,
    payload_path: Path | None = None,
    text: str | None = None,
    raw: bool = False,
) -> JstegResult:
    """Embed a jsteg payload into a baseline JPEG DCT coefficient stream."""

    _check_file(input_path, "JPEG 文件")
    payload = _load_payload(payload_path=payload_path, text=text)
    image = _read_jpeg_dct_image(input_path)
    carrier = payload if raw else _pack_jsteg_payload(payload)
    positions = list(_iter_jsteg_positions(image))
    capacity = len(positions) // 8
    if len(carrier) > capacity:
        available = capacity if raw else max(0, capacity - _JSTEG_HEADER_SIZE)
        raise ValueError(
            f"jsteg 容量不足：可写 {available} bytes，载荷需要 {len(payload)} bytes"
        )
    for bit, (component_index, row_index, offset) in zip(_iter_bits_lsb_first(carrier), positions):
        row = image.coefficients[component_index][row_index]
        row[offset] = _set_jsteg_lsb(row[offset], bit)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_jpeg_dct_image(image, output_path)
    written = output_path.stat().st_size if output_path.exists() else 0
    return JstegResult(
        operation="image.jsteg.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        width=image.width,
        height=image.height,
        capacity_bytes=capacity,
        payload_bytes=len(payload),
        written_bytes=written,
        raw=raw,
    )


def _pack_jsteg_payload(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("jsteg CLI length prefix 最大支持 4294967295 bytes")
    return _JSTEG_MAGIC + len(payload).to_bytes(4, "little") + payload


def _parse_jsteg_payload(stream: bytes) -> bytes:
    if len(stream) < _JSTEG_HEADER_SIZE:
        raise ValueError("jsteg 数据不足：缺少 magic/length 头")
    if stream[: len(_JSTEG_MAGIC)] != _JSTEG_MAGIC:
        raise ValueError("JPEG 不包含 jsteg CLI magic；如需原始 LSB 字节流请加 --raw")
    length = int.from_bytes(stream[5:9], "little")
    end = _JSTEG_HEADER_SIZE + length
    if end > len(stream):
        raise ValueError(f"jsteg 载荷长度异常：声明 {length} bytes，容量不足")
    return stream[_JSTEG_HEADER_SIZE:end]


def _load_payload(*, payload_path: Path | None, text: str | None) -> bytes:
    if payload_path is None and text is None:
        raise ValueError("jsteg hide 需要 --payload 或 --text")
    if payload_path is not None and text is not None:
        raise ValueError("jsteg hide 只能指定 --payload 或 --text 之一")
    if payload_path is not None:
        _check_file(payload_path, "载荷文件")
        return payload_path.read_bytes()
    assert text is not None
    return text.encode("utf-8")


def _read_lsb_stream(image) -> bytes:  # type: ignore[no-untyped-def]
    out = bytearray()
    bit_index = 0
    for component_index, row_index, offset in _iter_jsteg_positions(image):
        value = image.coefficients[component_index][row_index][offset]
        if bit_index == 0:
            out.append(0)
        out[-1] |= (value & 1) << bit_index
        bit_index = (bit_index + 1) & 7
    return bytes(out)


def _iter_bits_lsb_first(data: bytes) -> Iterator[int]:
    for byte in data:
        for bit_index in range(8):
            yield (byte >> bit_index) & 1


def _iter_jsteg_positions(image) -> Iterator[tuple[int, int, int]]:  # type: ignore[no-untyped-def]
    if not image.scan_components:
        raise ValueError("JPEG 缺少 scan component")
    component_index_by_id = {component["id"]: index for index, component in enumerate(image.components)}
    scan_component = image.scan_components[0]
    component_index = component_index_by_id[scan_component["id"]]
    mcus_x = (image.width + 8 * image.max_h - 1) // (8 * image.max_h)
    mcus_y = (image.height + 8 * image.max_v - 1) // (8 * image.max_v)
    for mcu_y in range(mcus_y):
        for mcu_x in range(mcus_x):
            for block_y in range(scan_component["v"]):
                out_y = mcu_y * scan_component["v"] + block_y
                if out_y >= len(image.coefficients[component_index]):
                    continue
                row = image.coefficients[component_index][out_y]
                for block_x in range(scan_component["h"]):
                    out_x = mcu_x * scan_component["h"] + block_x
                    base = out_x * 64
                    if base + 64 > len(row):
                        continue
                    for zigzag_index in range(1, 64):
                        offset = base + JPEG_ZIGZAG[zigzag_index]
                        value = row[offset]
                        if value < -1 or value > 1:
                            yield component_index, out_y, offset


def _jsteg_capacity_bytes(image) -> int:  # type: ignore[no-untyped-def]
    return sum(1 for _ in _iter_jsteg_positions(image)) // 8


def _set_jsteg_lsb(value: int, bit: int) -> int:
    if value == 0 or value == 1 or value == -1:
        raise ValueError("内部错误：jsteg 只能改写绝对值大于 1 的 AC 系数")
    sign = -1 if value < 0 else 1
    magnitude = abs(value)
    magnitude = (magnitude & ~1) | bit
    if magnitude <= 1:
        magnitude = 3 if bit else 2
    return sign * magnitude


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
