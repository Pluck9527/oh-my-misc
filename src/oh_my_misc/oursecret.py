from __future__ import annotations

import io
import os
import struct
import zipfile
from dataclasses import asdict, dataclass
from hashlib import md5
from pathlib import Path
from typing import Any

from Crypto.Cipher import Blowfish

TRAILER_SIZE = 28
TRAILER_MAGIC = b"HI"
BLOWFISH_KEY = b"Tonycat" + b"\x00" * 49
BMP_LSB_DATA_OFFSET = 0xE0


@dataclass(frozen=True)
class OurSecretEntry:
    name: str
    output_path: str
    size: int


@dataclass(frozen=True)
class OurSecretResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    carrier_format: str
    data_size: int
    encrypted_bytes: int
    payload_bytes: int
    password_tag: str
    password_verified: bool | None
    entries: list[dict[str, Any]]
    count: int
    written_bytes: int
    capacity_bytes: int = 0
    carrier_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _HiddenBlob:
    mode: str
    carrier_format: str
    encrypted: bytes
    data_size: int
    password_tag: bytes
    capacity_bytes: int = 0


def inspect_oursecret(carrier_path: Path, *, mode: str = "auto") -> OurSecretResult:
    blob = _find_hidden_blob(carrier_path, mode=mode)
    return OurSecretResult(
        operation="stego.oursecret.inspect",
        input_path=str(carrier_path),
        output_path="-",
        output_paths=[],
        mode=blob.mode,
        carrier_format=blob.carrier_format,
        data_size=blob.data_size,
        encrypted_bytes=len(blob.encrypted),
        payload_bytes=0,
        password_tag=blob.password_tag.hex(),
        password_verified=None,
        entries=[],
        count=1,
        written_bytes=0,
        capacity_bytes=blob.capacity_bytes,
        carrier_bytes=Path(carrier_path).stat().st_size,
    )


def extract_oursecret(
    carrier_path: Path,
    output_dir: Path,
    *,
    password: str | None = None,
    mode: str = "auto",
    overwrite: bool = False,
) -> OurSecretResult:
    blob = _find_hidden_blob(carrier_path, mode=mode)
    verified = None
    if password is not None:
        verified = password_tag(password) == blob.password_tag
        if not verified:
            raise ValueError("OurSecret password tag mismatch")
    plain = _decrypt(blob.encrypted)
    zip_payload = _truncate_zip_payload(plain)
    output_dir.mkdir(parents=True, exist_ok=True)
    entries: list[OurSecretEntry] = []
    output_paths: list[str] = []
    written_bytes = 0
    with zipfile.ZipFile(io.BytesIO(zip_payload)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            data = archive.read(info)
            target = _safe_output_path(output_dir, info.filename, overwrite=overwrite)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            entries.append(
                OurSecretEntry(name=info.filename, output_path=str(target), size=len(data))
            )
            output_paths.append(str(target))
            written_bytes += len(data)
    return OurSecretResult(
        operation="stego.oursecret.extract",
        input_path=str(carrier_path),
        output_path=str(output_dir),
        output_paths=output_paths,
        mode=blob.mode,
        carrier_format=blob.carrier_format,
        data_size=blob.data_size,
        encrypted_bytes=len(blob.encrypted),
        payload_bytes=len(zip_payload),
        password_tag=blob.password_tag.hex(),
        password_verified=verified,
        entries=[asdict(entry) for entry in entries],
        count=len(entries),
        written_bytes=written_bytes,
        capacity_bytes=blob.capacity_bytes,
        carrier_bytes=Path(carrier_path).stat().st_size,
    )


def hide_oursecret(
    carrier_path: Path,
    output_path: Path,
    *,
    payload_paths: list[Path] | None = None,
    text: str | None = None,
    text_name: str = "Message",
    password: str = "",
    mode: str = "append",
) -> OurSecretResult:
    _validate_hide_mode(mode)
    raw = _read_file(carrier_path, "载体文件")
    payload = _make_zip_payload(payload_paths=payload_paths or [], text=text, text_name=text_name)
    encrypted = _encrypt(payload)
    trailer = make_trailer(len(encrypted), password)
    capacity_bytes = 0
    if mode == "append":
        out = raw + encrypted + trailer
        carrier_format = "generic"
    else:
        pixel_offset = _bmp_pixel_offset(raw)
        pixels = bytearray(raw[pixel_offset:])
        required_pixel_bytes = BMP_LSB_DATA_OFFSET + len(encrypted) * 8
        if len(pixels) < required_pixel_bytes:
            raise ValueError(
                f"BMP LSB 容量不足：需要 {required_pixel_bytes} 个像素字节，实际 {len(pixels)}"
            )
        lsb_embed(pixels, 0, trailer)
        lsb_embed(pixels, BMP_LSB_DATA_OFFSET, encrypted)
        out = raw[:pixel_offset] + bytes(pixels)
        carrier_format = "bmp24"
        capacity_bytes = max(0, (len(pixels) - BMP_LSB_DATA_OFFSET) // 8)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(out)
    return OurSecretResult(
        operation="stego.oursecret.hide",
        input_path=str(carrier_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode=mode,
        carrier_format=carrier_format,
        data_size=len(encrypted),
        encrypted_bytes=len(encrypted),
        payload_bytes=len(payload),
        password_tag=password_tag(password).hex(),
        password_verified=True,
        entries=[],
        count=1,
        written_bytes=output_path.stat().st_size,
        capacity_bytes=capacity_bytes,
        carrier_bytes=len(raw),
    )


def password_tag(password: str) -> bytes:
    return bytes(byte ^ 0x08 for byte in md5(password.encode()).digest())[:16]


def make_trailer(data_size: int, password: str) -> bytes:
    if data_size < 0 or data_size > 0xFFFFFFFF:
        raise ValueError("OurSecret 数据长度超出 32-bit trailer 范围")
    trailer = bytearray(TRAILER_SIZE)
    trailer[:2] = TRAILER_MAGIC
    struct.pack_into("<I", trailer, 4, data_size)
    trailer[8:24] = password_tag(password)
    trailer[24] = 0
    return bytes(trailer)


def check_trailer(trailer: bytes) -> tuple[int, bytes] | None:
    if len(trailer) < TRAILER_SIZE or trailer[:2] != TRAILER_MAGIC:
        return None
    return struct.unpack_from("<I", trailer, 4)[0], trailer[8:24]


def lsb_embed(pixels: bytearray, offset: int, data: bytes) -> None:
    pos = offset
    if pos < 0 or pos + len(data) * 8 > len(pixels):
        raise ValueError("LSB 写入范围超出像素数据")
    for byte in data:
        for bit_index in range(8):
            bit = (byte >> (7 - bit_index)) & 1
            pixels[pos] = (pixels[pos] & 0xFE) | bit
            pos += 1


def lsb_extract(pixels: bytes, offset: int, size: int) -> bytes:
    pos = offset
    if size < 0 or pos < 0 or pos + size * 8 > len(pixels):
        raise ValueError("LSB 读取范围超出像素数据")
    out = bytearray()
    for _ in range(size):
        value = 0
        for _ in range(8):
            value = (value << 1) | (pixels[pos] & 1)
            pos += 1
        out.append(value)
    return bytes(out)


def _find_hidden_blob(carrier_path: Path, *, mode: str) -> _HiddenBlob:
    _validate_mode(mode)
    raw = _read_file(carrier_path, "载体文件")
    errors: list[str] = []
    if mode in {"auto", "append"}:
        try:
            return _find_append_blob(raw)
        except ValueError as error:
            if mode == "append":
                raise
            errors.append(str(error))
    if mode in {"auto", "lsb"}:
        try:
            return _find_lsb_blob(raw)
        except ValueError as error:
            if mode == "lsb":
                raise
            errors.append(str(error))
    raise ValueError("未找到 OurSecret 隐藏数据" + (f"：{'; '.join(errors)}" if errors else ""))


def _find_append_blob(raw: bytes) -> _HiddenBlob:
    if len(raw) < TRAILER_SIZE:
        raise ValueError("append 模式载体太短")
    info = check_trailer(raw[-TRAILER_SIZE:])
    if info is None:
        raise ValueError("append 模式未找到 HI trailer")
    data_size, tag = info
    start = len(raw) - TRAILER_SIZE - data_size
    if start < 0:
        raise ValueError("append 模式数据长度越界")
    encrypted = raw[start : len(raw) - TRAILER_SIZE]
    return _HiddenBlob(
        mode="append",
        carrier_format="generic",
        encrypted=encrypted,
        data_size=data_size,
        password_tag=tag,
    )


def _find_lsb_blob(raw: bytes) -> _HiddenBlob:
    pixel_offset = _bmp_pixel_offset(raw)
    pixels = raw[pixel_offset:]
    trailer = lsb_extract(pixels, 0, TRAILER_SIZE)
    info = check_trailer(trailer)
    if info is None:
        raise ValueError("BMP LSB 模式未找到 HI trailer")
    data_size, tag = info
    capacity_bytes = max(0, (len(pixels) - BMP_LSB_DATA_OFFSET) // 8)
    if data_size > capacity_bytes:
        raise ValueError(f"BMP LSB 数据长度越界：{data_size} > {capacity_bytes}")
    encrypted = lsb_extract(pixels, BMP_LSB_DATA_OFFSET, data_size)
    return _HiddenBlob(
        mode="lsb",
        carrier_format="bmp24",
        encrypted=encrypted,
        data_size=data_size,
        password_tag=tag,
        capacity_bytes=capacity_bytes,
    )


def _make_zip_payload(*, payload_paths: list[Path], text: str | None, text_name: str) -> bytes:
    if text is None and not payload_paths:
        raise ValueError("oursecret hide 需要 --payload 或 --text")
    if text is not None and payload_paths:
        raise ValueError("oursecret hide 只能在 --payload 和 --text 中选择一种输入")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        if text is not None:
            archive.writestr(_archive_name(text_name), text.encode("utf-8"))
        else:
            used: set[str] = set()
            for path in payload_paths:
                data = _read_file(path, "载荷文件")
                name = _dedupe_name(_archive_name(path.name), used)
                archive.writestr(name, data)
    return buf.getvalue()


def _archive_name(name: str) -> str:
    base = os.path.basename(name) or "Message"
    return base.replace("\x00", "_") or "Message"


def _dedupe_name(name: str, used: set[str]) -> str:
    if name not in used:
        used.add(name)
        return name
    stem = Path(name).stem or "file"
    suffix = Path(name).suffix
    counter = 1
    while True:
        candidate = f"{stem}_{counter}{suffix}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        counter += 1


def _safe_output_path(output_dir: Path, archive_name: str, *, overwrite: bool) -> Path:
    target = output_dir / _archive_name(archive_name)
    if overwrite or not target.exists():
        return target
    stem = target.stem or "out"
    suffix = target.suffix
    counter = 1
    while True:
        candidate = target.with_name(f"{stem}_{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def _truncate_zip_payload(data: bytes) -> bytes:
    end = data.rfind(b"PK\x05\x06")
    if end < 0:
        return data.rstrip(b"\x00")
    if end + 22 > len(data):
        return data[: end + 22]
    comment_length = struct.unpack_from("<H", data, end + 20)[0]
    return data[: end + 22 + comment_length]


def _encrypt(data: bytes) -> bytes:
    pad = (-len(data)) % Blowfish.block_size
    return _cipher().encrypt(data + b"\x00" * pad)


def _decrypt(data: bytes) -> bytes:
    if len(data) % Blowfish.block_size:
        data = data[: len(data) - len(data) % Blowfish.block_size]
    return _cipher().decrypt(data)


def _cipher() -> Blowfish.BlowfishCipher:
    return Blowfish.new(BLOWFISH_KEY, Blowfish.MODE_ECB)


def _bmp_pixel_offset(raw: bytes) -> int:
    if len(raw) < 54 or raw[:2] != b"BM":
        raise ValueError("LSB 模式仅支持 BMP 载体")
    bit_count = struct.unpack_from("<H", raw, 28)[0]
    if bit_count != 24:
        raise ValueError("LSB 模式仅支持 24-bit BMP 载体")
    pixel_offset = struct.unpack_from("<I", raw, 10)[0]
    if pixel_offset >= len(raw):
        raise ValueError("BMP pixel offset 越界")
    return pixel_offset


def _validate_mode(mode: str) -> None:
    if mode not in {"auto", "append", "lsb"}:
        raise ValueError("mode 必须是 auto、append 或 lsb")


def _validate_hide_mode(mode: str) -> None:
    if mode not in {"append", "lsb"}:
        raise ValueError("hide mode 必须是 append 或 lsb")


def _read_file(path: Path, label: str) -> bytes:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
    return Path(path).read_bytes()
