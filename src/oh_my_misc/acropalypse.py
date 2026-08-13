from __future__ import annotations

import io
import struct
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

from PIL import Image

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class AcropalypseRestoreResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    width: int
    height: int
    mode: str
    trailing_bytes: int
    recovered_bytes: int
    bit_offset: int
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _PngInfo:
    width: int
    height: int
    iend_end: int


def restore_acropalypse_png(
    input_path: Path,
    output_path: Path,
    *,
    width: int = 1920,
    height: int = 1080,
    mode: str = "rgba",
) -> AcropalypseRestoreResult:
    """Restore a cropped Windows Snipping Tool / aCropalypse PNG from trailing data."""

    if width < 1 or height < 1:
        raise ValueError("原图宽高必须大于 0")
    if mode not in {"rgb", "rgba"}:
        raise ValueError("mode 必须是 rgb 或 rgba")
    data = _read_png(input_path)
    info = _parse_png_until_iend(data)
    trailer = data[info.iend_end :]
    if not trailer:
        raise ValueError("IEND 后没有残留数据，未检测到可恢复的 acropalypse 尾部")
    idat = _extract_trailing_idat(trailer)
    recovered, bit_offset = _recover_deflate_suffix(idat)
    channels = 4 if mode == "rgba" else 3
    row = b"\x00" + (b"\xff\x00\xff\xff" if mode == "rgba" else b"\xff\x00\xff") * width
    image_bytes = bytearray(row * height)
    if len(recovered) > len(image_bytes):
        raise ValueError(
            f"恢复数据超过目标画布：{len(recovered)} bytes > {len(image_bytes)} bytes"
        )
    image_bytes[-len(recovered) :] = recovered
    color_type = 6 if channels == 4 else 2
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_png(output_path, width, height, color_type, bytes(image_bytes))
    with Image.open(output_path) as restored:
        restored.verify()
    return AcropalypseRestoreResult(
        operation="image.acropalypse.restore",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        width=width,
        height=height,
        mode=mode,
        trailing_bytes=len(trailer),
        recovered_bytes=len(recovered),
        bit_offset=bit_offset,
    )

def _read_png(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"文件不存在：{path}")
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("不是有效 PNG 文件")
    return data


def _parse_png_until_iend(data: bytes) -> _PngInfo:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("不是有效 PNG 文件")
    pos = len(PNG_SIGNATURE)
    width: int | None = None
    height: int | None = None
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type = data[pos + 4 : pos + 8]
        body_start = pos + 8
        body_end = body_start + length
        chunk_end = body_end + 4
        if chunk_end > len(data):
            raise ValueError("PNG chunk 长度越界")
        if chunk_type == b"IHDR":
            if length != 13:
                raise ValueError("IHDR 长度异常")
            width, height = struct.unpack(">II", data[body_start : body_start + 8])
        if chunk_type == b"IEND":
            if width is None or height is None:
                raise ValueError("缺少 IHDR")
            return _PngInfo(width=width, height=height, iend_end=chunk_end)
        pos = chunk_end
    raise ValueError("缺少 IEND chunk")


def _parse_png_chunk(stream: io.BytesIO) -> tuple[bytes, bytes] | None:
    length_data = stream.read(4)
    if not length_data:
        return None
    if len(length_data) != 4:
        raise ValueError("残留 PNG chunk 长度字段不完整")
    length = struct.unpack(">I", length_data)[0]
    chunk_type = stream.read(4)
    body = stream.read(length)
    crc = stream.read(4)
    if len(chunk_type) != 4 or len(body) != length or len(crc) != 4:
        raise ValueError("残留 PNG chunk 不完整")
    expected_crc = zlib.crc32(chunk_type + body) & 0xFFFFFFFF
    actual_crc = struct.unpack(">I", crc)[0]
    if expected_crc != actual_crc:
        raise ValueError(f"残留 PNG chunk CRC 不匹配：{chunk_type!r}")
    return chunk_type, body


def _extract_trailing_idat(trailer: bytes) -> bytes:
    try:
        next_idat = trailer.index(b"IDAT", 12)
    except ValueError as error:
        raise ValueError("IEND 后没有找到残留 IDAT chunk") from error
    raw_prefix = trailer[12 : max(12, next_idat - 8)]
    stream = io.BytesIO(trailer[next_idat - 4 :])
    full_idat = bytearray(raw_prefix)
    while True:
        chunk = _parse_png_chunk(stream)
        if chunk is None:
            raise ValueError("残留数据里没有 IEND chunk")
        chunk_type, body = chunk
        if chunk_type == b"IDAT":
            full_idat.extend(body)
        elif chunk_type == b"IEND":
            break
        else:
            raise ValueError(f"残留数据中出现非预期 chunk：{chunk_type!r}")
    if len(full_idat) <= 4:
        raise ValueError("残留 IDAT 数据不足")
    return bytes(full_idat[:-4])


def _recover_deflate_suffix(idat: bytes) -> tuple[bytes, int]:
    bitstream: list[int] = []
    for byte in idat:
        bitstream.extend((byte >> bit) & 1 for bit in range(8))
    bitstream.extend([0] * 7)

    shifted_streams: list[bytes] = []
    for offset in range(8):
        shifted = bytearray()
        for index in range(offset, len(bitstream) - 7, 8):
            value = 0
            for bit in range(8):
                value |= bitstream[index + bit] << bit
            shifted.append(value)
        shifted_streams.append(bytes(shifted))

    prefix_length = 0x8000
    prefix = (
        b"\x00"
        + prefix_length.to_bytes(2, "little")
        + (prefix_length ^ 0xFFFF).to_bytes(2, "little")
        + b"\x00" * prefix_length
    )
    for bit_offset in range(len(idat)):
        candidate = shifted_streams[bit_offset % 8][bit_offset // 8 :]
        if not candidate or _deflate_block_type(candidate[0]) == 3:
            continue
        decompressor = zlib.decompressobj(wbits=-15)
        try:
            recovered = decompressor.decompress(prefix + candidate) + decompressor.flush(
                zlib.Z_FINISH
            )
        except zlib.error:
            continue
        if decompressor.eof and decompressor.unused_data in (b"", b"\x00"):
            return recovered[prefix_length:], bit_offset
    raise ValueError("未找到可解析的残留 DEFLATE 数据")


def _deflate_block_type(first_byte: int) -> int:
    return (first_byte >> 1) & 0b11


def _write_png(path: Path, width: int, height: int, color_type: int, scanlines: bytes) -> None:
    with path.open("wb") as stream:
        stream.write(PNG_SIGNATURE)
        _write_chunk(
            stream,
            b"IHDR",
            struct.pack(">II5B", width, height, 8, color_type, 0, 0, 0),
        )
        _write_chunk(stream, b"IDAT", zlib.compress(scanlines))
        _write_chunk(stream, b"IEND", b"")


def _write_chunk(stream: io.BufferedWriter, chunk_type: bytes, body: bytes) -> None:
    stream.write(struct.pack(">I", len(body)))
    stream.write(chunk_type)
    stream.write(body)
    stream.write(struct.pack(">I", zlib.crc32(chunk_type + body) & 0xFFFFFFFF))
