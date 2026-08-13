from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_FIELD_SPECS: dict[str, tuple[int, int]] = {
    "private": (2, 0),
    "padding": (2, 1),
    "original": (3, 2),
    "copyright": (3, 3),
    "protection": (1, 0),
}

FIELD_CHOICES = tuple(_FIELD_SPECS)
_MAGIC_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("zip", b"PK\x03\x04"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("pdf", b"%PDF-"),
    ("gif87a", b"GIF87a"),
    ("gif89a", b"GIF89a"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("gzip", b"\x1f\x8b\x08"),
    ("bmp", b"BM"),
)
_FLAG_RE = re.compile(rb"flag\{[^\r\n\x00]{0,200}\}", re.IGNORECASE)


@dataclass(frozen=True)
class MP3FrameInfo:
    offset: int
    frame_length: int
    version: str
    layer: str
    bitrate_kbps: int
    sample_rate: int
    padding: int
    private: int
    copyright: int
    original: int
    protection: int


@dataclass(frozen=True)
class MP3FieldStegoResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    field: str | None
    fields: list[str]
    start: int
    end: int
    order: str | None
    orders: list[str]
    frame_count: int
    bit_count: int
    written_bytes: int
    output_format: str
    base_frame_size: int | None
    parsed_frames: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


def extract_mp3_frame_field(
    input_path: Path,
    output_path: Path,
    *,
    field: str = "copyright",
    start: int | None = None,
    end: int | None = None,
    order: str = "msb",
    limit_bits: int | None = None,
    output_format: str = "bytes",
    base_frame_size: int | None = None,
) -> MP3FieldStegoResult:
    """Extract a bit stream stored in one MPEG audio frame-header field."""

    data = _read_file(input_path)
    _validate_field(field)
    _validate_order(order)
    _validate_limit(limit_bits)
    _validate_output_format(output_format)
    region_start, region_end = _normalise_region(data, start, end)
    bits, frames, parsed_frames = _extract_bits(
        data,
        field=field,
        start=region_start,
        end=region_end,
        limit_bits=limit_bits,
        base_frame_size=base_frame_size,
    )
    payload = _render_bits(bits, order=order, output_format=output_format)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return MP3FieldStegoResult(
        operation="audio.mp3-field.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        field=field,
        fields=[field],
        start=region_start,
        end=region_end,
        order=order,
        orders=[order],
        frame_count=frames,
        bit_count=len(bits),
        written_bytes=len(payload),
        output_format=output_format,
        base_frame_size=base_frame_size,
        parsed_frames=parsed_frames,
        findings=_find_payload_hints(payload if output_format != "bits" else _bits_to_bytes(bits, order=order)),
    )


def scan_mp3_frame_fields(
    input_path: Path,
    output_dir: Path,
    *,
    fields: Iterable[str] = ("copyright", "private", "original"),
    start: int | None = None,
    end: int | None = None,
    orders: Sequence[str] = ("msb", "lsb"),
    limit_bits: int | None = None,
    base_frame_size: int | None = None,
    write_all: bool = False,
) -> MP3FieldStegoResult:
    """Scan common MP3 frame-header fields for hidden bytes and write candidates."""

    data = _read_file(input_path)
    field_list = [item for item in fields]
    if not field_list:
        raise ValueError("fields 不能为空")
    for item in field_list:
        _validate_field(item)
    order_list = list(orders)
    if not order_list:
        raise ValueError("orders 不能为空")
    for item in order_list:
        _validate_order(item)
    _validate_limit(limit_bits)
    region_start, region_end = _normalise_region(data, start, end)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_paths: list[str] = []
    findings: list[dict[str, Any]] = []
    max_frames = 0
    max_bits = 0
    parsed_frames_any = False
    for field_name in field_list:
        bits, frames, parsed_frames = _extract_bits(
            data,
            field=field_name,
            start=region_start,
            end=region_end,
            limit_bits=limit_bits,
            base_frame_size=base_frame_size,
        )
        max_frames = max(max_frames, frames)
        max_bits = max(max_bits, len(bits))
        parsed_frames_any = parsed_frames_any or parsed_frames
        for order in order_list:
            payload = _bits_to_bytes(bits, order=order)
            hints = _find_payload_hints(payload)
            if hints or write_all:
                candidate = output_dir / f"{field_name}-{order}.bin"
                candidate.write_bytes(payload)
                output_paths.append(str(candidate))
                if hints:
                    for hint in hints:
                        enriched = dict(hint)
                        enriched.update(
                            {
                                "field": field_name,
                                "order": order,
                                "output_path": str(candidate),
                            }
                        )
                        findings.append(enriched)
                else:
                    findings.append(
                        {
                            "kind": "raw",
                            "offset": 0,
                            "field": field_name,
                            "order": order,
                            "output_path": str(candidate),
                        }
                    )
    manifest = output_dir / "manifest.json"
    manifest_payload = {
        "status": "success",
        "operation": "audio.mp3-field.scan",
        "input_path": str(input_path),
        "start": region_start,
        "end": region_end,
        "fields": field_list,
        "orders": order_list,
        "limit_bits": limit_bits,
        "base_frame_size": base_frame_size,
        "parsed_frames": parsed_frames_any,
        "frame_count": max_frames,
        "bit_count": max_bits,
        "write_all": write_all,
        "findings": findings,
        "output_paths": [str(manifest), *output_paths],
    }
    manifest.write_text(json.dumps(manifest_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    output_paths.insert(0, str(manifest))
    return MP3FieldStegoResult(
        operation="audio.mp3-field.scan",
        input_path=str(input_path),
        output_path=str(manifest),
        output_paths=output_paths,
        field=None,
        fields=field_list,
        start=region_start,
        end=region_end,
        order=None,
        orders=order_list,
        frame_count=max_frames,
        bit_count=max_bits,
        written_bytes=sum(Path(path).stat().st_size for path in output_paths if Path(path).exists()),
        output_format="bytes",
        base_frame_size=base_frame_size,
        parsed_frames=parsed_frames_any,
        findings=findings,
        count=len(output_paths),
    )


def _read_file(input_path: Path) -> bytes:
    if not input_path.is_file():
        raise FileNotFoundError(f"MP3 文件不存在：{input_path}")
    data = input_path.read_bytes()
    if len(data) < 4:
        raise ValueError("MP3 文件太短")
    return data


def _normalise_region(data: bytes, start: int | None, end: int | None) -> tuple[int, int]:
    region_start = _skip_id3v2(data) if start is None else start
    region_end = len(data) if end is None else end
    if region_start < 0 or region_end < 0 or region_start > len(data) or region_end > len(data):
        raise ValueError(f"start/end 超出文件范围：start={region_start} end={region_end} size={len(data)}")
    if region_end <= region_start:
        raise ValueError(f"end 必须大于 start：start={region_start} end={region_end}")
    return region_start, region_end


def _skip_id3v2(data: bytes) -> int:
    if len(data) >= 10 and data[:3] == b"ID3" and all(byte < 0x80 for byte in data[6:10]):
        size = (data[6] << 21) | (data[7] << 14) | (data[8] << 7) | data[9]
        footer = 10 if data[5] & 0x10 else 0
        return min(len(data), 10 + size + footer)
    return 0


def _extract_bits(
    data: bytes,
    *,
    field: str,
    start: int,
    end: int,
    limit_bits: int | None,
    base_frame_size: int | None,
) -> tuple[list[int], int, bool]:
    bits: list[int] = []
    frames = 0
    offset = start
    if base_frame_size is not None:
        if base_frame_size <= 0:
            raise ValueError("base_frame_size 必须大于 0")
        while offset + 4 <= end and (limit_bits is None or len(bits) < limit_bits):
            header = data[offset : offset + 4]
            if len(header) < 4:
                break
            bits.append(_read_field_bit(header, field))
            frames += 1
            padding = (header[2] >> 1) & 1
            offset += base_frame_size + padding
        if not bits:
            raise ValueError("指定区域没有可提取的数据")
        return bits, frames, False

    while offset + 4 <= end and (limit_bits is None or len(bits) < limit_bits):
        frame = _parse_frame(data, offset)
        if frame is None or offset + frame.frame_length > end:
            next_offset = _find_next_frame(data, offset + 1, end)
            if next_offset is None:
                break
            offset = next_offset
            continue
        bits.append(_read_field_bit(data[offset : offset + 4], field))
        frames += 1
        offset += frame.frame_length
    if not bits:
        raise ValueError("指定区域未找到有效 MP3 帧")
    return bits, frames, True


def _find_next_frame(data: bytes, start: int, end: int) -> int | None:
    limit = max(start, end - 3)
    for offset in range(start, limit):
        if data[offset] == 0xFF and data[offset + 1] & 0xE0 == 0xE0 and _parse_frame(data, offset):
            return offset
    return None


def _read_field_bit(header: bytes, field: str) -> int:
    byte_offset, shift = _FIELD_SPECS[field]
    return (header[byte_offset] >> shift) & 1


def _parse_frame(data: bytes, offset: int) -> MP3FrameInfo | None:
    if offset + 4 > len(data):
        return None
    b0, b1, b2, b3 = data[offset : offset + 4]
    if b0 != 0xFF or b1 & 0xE0 != 0xE0:
        return None
    version_bits = (b1 >> 3) & 0b11
    layer_bits = (b1 >> 1) & 0b11
    if version_bits == 0b01 or layer_bits == 0:
        return None
    bitrate_index = (b2 >> 4) & 0b1111
    sample_index = (b2 >> 2) & 0b11
    if bitrate_index in {0, 15} or sample_index == 3:
        return None
    version = {0: "2.5", 2: "2", 3: "1"}[version_bits]
    layer = {1: "III", 2: "II", 3: "I"}[layer_bits]
    bitrate = _bitrate_kbps(version_bits, layer_bits, bitrate_index)
    sample_rate = _sample_rate(version_bits, sample_index)
    padding = (b2 >> 1) & 1
    if layer == "I":
        frame_length = ((12 * bitrate * 1000) // sample_rate + padding) * 4
    elif layer == "III" and version != "1":
        frame_length = (72 * bitrate * 1000) // sample_rate + padding
    else:
        frame_length = (144 * bitrate * 1000) // sample_rate + padding
    if frame_length < 4:
        return None
    return MP3FrameInfo(
        offset=offset,
        frame_length=frame_length,
        version=f"MPEG-{version}",
        layer=f"Layer {layer}",
        bitrate_kbps=bitrate,
        sample_rate=sample_rate,
        padding=padding,
        private=b2 & 1,
        copyright=(b3 >> 3) & 1,
        original=(b3 >> 2) & 1,
        protection=b1 & 1,
    )


def _bitrate_kbps(version_bits: int, layer_bits: int, index: int) -> int:
    if version_bits == 3 and layer_bits == 3:
        table = [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448]
    elif version_bits == 3 and layer_bits == 2:
        table = [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384]
    elif version_bits == 3:
        table = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]
    elif layer_bits == 3:
        table = [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256]
    else:
        table = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]
    return table[index]


def _sample_rate(version_bits: int, index: int) -> int:
    return {
        3: [44100, 48000, 32000],
        2: [22050, 24000, 16000],
        0: [11025, 12000, 8000],
    }[version_bits][index]


def _render_bits(bits: Sequence[int], *, order: str, output_format: str) -> bytes:
    if output_format == "bits":
        return "".join(str(bit) for bit in bits).encode("ascii")
    return _bits_to_bytes(bits, order=order)


def _bits_to_bytes(bits: Sequence[int], *, order: str) -> bytes:
    padded = list(bits)
    while len(padded) % 8:
        padded.append(0)
    output = bytearray()
    for index in range(0, len(padded), 8):
        value = 0
        chunk = padded[index : index + 8]
        if order == "msb":
            for bit in chunk:
                value = (value << 1) | bit
        else:
            for shift, bit in enumerate(chunk):
                value |= bit << shift
        output.append(value)
    return bytes(output)


def _find_payload_hints(payload: bytes, *, search_window: int = 4096) -> list[dict[str, Any]]:
    window = payload[:search_window]
    findings: list[dict[str, Any]] = []
    for kind, signature in _MAGIC_SIGNATURES:
        offset = window.find(signature)
        if offset >= 0:
            findings.append({"kind": kind, "offset": offset})
    for match in _FLAG_RE.finditer(window):
        findings.append(
            {
                "kind": "flag",
                "offset": match.start(),
                "text": match.group(0).decode("utf-8", errors="replace"),
            }
        )
    if not findings:
        preview = _printable_preview(payload)
        if preview:
            findings.append({"kind": "text-preview", "offset": 0, "text": preview})
    return findings


def _printable_preview(payload: bytes) -> str:
    stripped = payload.rstrip(b"\x00")[:160]
    if len(stripped) < 4:
        return ""
    printable = sum(1 for byte in stripped if byte in b"\t\r\n" or 32 <= byte <= 126)
    if printable / len(stripped) < 0.85:
        return ""
    return stripped.decode("utf-8", errors="replace")


def _validate_field(field: str) -> None:
    if field not in _FIELD_SPECS:
        raise ValueError(f"field 必须是 {', '.join(FIELD_CHOICES)} 之一：{field}")


def _validate_order(order: str) -> None:
    if order not in {"msb", "lsb"}:
        raise ValueError(f"order 必须是 msb 或 lsb：{order}")


def _validate_output_format(output_format: str) -> None:
    if output_format not in {"bytes", "bits"}:
        raise ValueError(f"format 必须是 bytes 或 bits：{output_format}")


def _validate_limit(limit_bits: int | None) -> None:
    if limit_bits is not None and limit_bits <= 0:
        raise ValueError("limit_bits 必须大于 0")
