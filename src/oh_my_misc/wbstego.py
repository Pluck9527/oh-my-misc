from __future__ import annotations

import math
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class WbStegoResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    carrier_format: str
    bit_count: int
    compression: int
    capacity_bytes: int
    payload_bytes: int = 0
    written_bytes: int = 0
    embedded_extension: str = ""
    distributed: bool = False
    count: int = 1
    password_protected: bool = False
    password_verified: bool = False
    found_password: str | None = None
    attempts: int = 0

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _BmpInfo:
    data: bytearray
    pixel_offset: int
    bit_count: int
    compression: int
    dib_size: int
    capacity_bytes: int


def hide_wbstego_bmp(
    input_path: Path,
    output_path: Path,
    payload_path: Path,
    *,
    distribute: bool = False,
    password: str | None = None,
    crypt: bool = True,
    mix: bool = False,
    transmit_password: bool = False,
) -> WbStegoResult:
    """Embed data in a BMP like wbStego4open's no-password BMP mode."""

    _check_file(input_path, "BMP 文件")
    _check_file(payload_path, "载荷文件")
    bmp = _read_bmp(input_path)
    extension = _extension3(payload_path)
    payload = _prepend_ext(extension, payload_path.read_bytes())
    if password is not None:
        payload = _encrypt_wbstego_payload(
            payload,
            password,
            crypt=crypt,
            mix=mix,
            transmit_password=transmit_password,
        )
    if distribute:
        payload = _distribute(payload, bmp.capacity_bytes)
    else:
        payload = _prepend_size(payload, len(payload))
    if len(payload) > bmp.capacity_bytes:
        raise ValueError(f"wbStego BMP 容量不足：需要 {len(payload)} bytes，可用 {bmp.capacity_bytes} bytes")
    if bmp.bit_count == 24 or bmp.bit_count == 8 and bmp.compression == 0:
        _embed_lsb_1bit(bmp.data, bmp.pixel_offset, payload)
    elif bmp.bit_count == 4 and bmp.compression == 0:
        _embed_nibble_lsb_2bit(bmp.data, bmp.pixel_offset, payload)
    elif bmp.bit_count == 8 and bmp.compression == 1:
        _embed_rle8_lsb(bmp.data, bmp.pixel_offset, payload)
    elif bmp.bit_count == 4 and bmp.compression == 2:
        _embed_rle4_nibble_lsb(bmp.data, bmp.pixel_offset, payload)
    else:
        raise ValueError("当前原生实现支持 24/8/4-bit BMP，以及 8-bit RLE/4-bit RLE BMP")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bmp.data)
    return WbStegoResult(
        operation="image.wbstego.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format="BMP",
        bit_count=bmp.bit_count,
        compression=bmp.compression,
        capacity_bytes=bmp.capacity_bytes,
        payload_bytes=payload_path.stat().st_size,
        written_bytes=output_path.stat().st_size,
        embedded_extension=extension.replace("/", ""),
        distributed=distribute,
        password_protected=password is not None,
    )


def extract_wbstego_bmp(input_path: Path, output_path: Path, *, password: str | None = None) -> WbStegoResult:
    """Extract wbStego4open no-password BMP payload."""

    _check_file(input_path, "BMP 文件")
    bmp = _read_bmp(input_path)
    if bmp.bit_count == 24 or bmp.bit_count == 8 and bmp.compression == 0:
        stream = _extract_lsb_1bit(bmp.data, bmp.pixel_offset, bmp.capacity_bytes)
    elif bmp.bit_count == 4 and bmp.compression == 0:
        stream = _extract_nibble_lsb_2bit(bmp.data, bmp.pixel_offset, bmp.capacity_bytes)
    elif bmp.bit_count == 8 and bmp.compression == 1:
        stream = _extract_rle8_lsb(bmp.data, bmp.pixel_offset, bmp.capacity_bytes)
    elif bmp.bit_count == 4 and bmp.compression == 2:
        stream = _extract_rle4_nibble_lsb(bmp.data, bmp.pixel_offset, bmp.capacity_bytes)
    else:
        raise ValueError("当前原生实现支持 24/8/4-bit BMP，以及 8-bit RLE/4-bit RLE BMP")
    if len(stream) < 3:
        raise ValueError("wbStego 数据不足，缺少长度字段")
    stored_size = _read_size24(stream[:3])
    if stored_size > len(stream) - 3:
        raise ValueError(f"wbStego 长度异常：{stored_size} > {len(stream) - 3}")
    data = bytes(stream[3 : 3 + stored_size])
    distributed = _is_distributed(data, bmp.capacity_bytes)
    if distributed:
        data = _undistribute(data, bmp.capacity_bytes)
    password_verified = False
    if password is not None:
        data, password_verified = _decrypt_wbstego_payload(data, password)
    if len(data) < 3:
        raise ValueError("wbStego 数据缺少 3 字符扩展名")
    extension = data[:3].decode("latin1", errors="replace")
    payload = data[3:]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return WbStegoResult(
        operation="image.wbstego.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format="BMP",
        bit_count=bmp.bit_count,
        compression=bmp.compression,
        capacity_bytes=bmp.capacity_bytes,
        payload_bytes=len(payload),
        written_bytes=len(payload),
        embedded_extension=extension.replace("/", ""),
        distributed=distributed,
        password_protected=password is not None,
        password_verified=password_verified,
    )


def analyse_wbstego_bmp(input_path: Path) -> WbStegoResult:
    _check_file(input_path, "BMP 文件")
    bmp = _read_bmp(input_path)
    return WbStegoResult(
        operation="image.wbstego.analyse",
        input_path=str(input_path),
        output_path="",
        output_paths=[],
        carrier_format="BMP",
        bit_count=bmp.bit_count,
        compression=bmp.compression,
        capacity_bytes=bmp.capacity_bytes,
    )


def _read_bmp(path: Path) -> _BmpInfo:
    data = bytearray(path.read_bytes())
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("不是 BMP 文件")
    pixel_offset = int.from_bytes(data[10:14], "little")
    dib_size = int.from_bytes(data[14:18], "little")
    if len(data) < 14 + dib_size or dib_size < 16:
        raise ValueError("BMP DIB header 不完整")
    bit_count = int.from_bytes(data[28:30], "little")
    compression = int.from_bytes(data[30:34], "little") if dib_size >= 40 else 0
    if pixel_offset >= len(data):
        raise ValueError("BMP pixel offset 越界")
    pixel_bytes = len(data) - pixel_offset
    if compression == 0 and bit_count in {24, 8}:
        capacity = pixel_bytes // 8
    elif compression == 0 and bit_count == 4:
        capacity = (pixel_bytes * 2) // 8
    elif compression == 1 and bit_count == 8:
        capacity = len(_bmp_rle_carrier_positions(data[pixel_offset:], 8)) // 8
    elif compression == 2 and bit_count == 4:
        capacity = (len(_bmp_rle_carrier_positions(data[pixel_offset:], 4)) * 2) // 8
    else:
        raise ValueError(
            f"当前原生实现支持 24/8/4-bit BMP 与 8/4-bit RLE BMP，"
            f"当前为 {bit_count}-bit compression={compression}"
        )
    return _BmpInfo(data, pixel_offset, bit_count, compression, dib_size, capacity)


def _embed_lsb_1bit(data: bytearray, offset: int, payload: bytes) -> None:
    pos = offset
    for byte in payload:
        for bit in range(7, -1, -1):
            data[pos] = (data[pos] & 0xFE) | ((byte >> bit) & 1)
            pos += 1


def _extract_lsb_1bit(data: bytearray, offset: int, capacity: int) -> bytes:
    out = bytearray()
    pos = offset
    for _ in range(capacity):
        value = 0
        for bit in range(7, -1, -1):
            value |= (data[pos] & 1) << bit
            pos += 1
        out.append(value)
    return bytes(out)


def _embed_nibble_lsb_2bit(data: bytearray, offset: int, payload: bytes) -> None:
    pos = offset
    for byte in payload:
        for pair in range(3, -1, -1):
            high = (byte >> (2 * pair + 1)) & 1
            low = (byte >> (2 * pair)) & 1
            data[pos] = (data[pos] & 0xEE) | (high << 4) | low
            pos += 1


def _extract_nibble_lsb_2bit(data: bytearray, offset: int, capacity: int) -> bytes:
    out = bytearray()
    pos = offset
    for _ in range(capacity):
        value = 0
        for pair in range(3, -1, -1):
            value |= ((data[pos] & 0x10) >> 4) << (2 * pair + 1)
            value |= (data[pos] & 1) << (2 * pair)
            pos += 1
        out.append(value)
    return bytes(out)


def _bmp_rle_carrier_positions(stream: bytes, bit_count: int) -> list[int]:
    positions: list[int] = []
    pos = 0
    size = len(stream)
    while pos + 1 < size:
        count = stream[pos]
        value_pos = pos + 1
        value = stream[value_pos]
        pos += 2
        if count:
            positions.append(value_pos)
            continue
        if value == 0:  # end of line
            continue
        if value == 1:  # end of bitmap
            break
        if value == 2:  # delta
            pos += 2
            continue
        if bit_count == 8:
            run = value
            positions.extend(range(pos, min(pos + run, size)))
            pos += run + (run & 1)
        else:
            byte_count = (value + 1) // 2
            positions.extend(range(pos, min(pos + byte_count, size)))
            pos += byte_count
            if byte_count & 1:
                pos += 1
    return positions


def _embed_rle8_lsb(data: bytearray, offset: int, payload: bytes) -> None:
    positions = _bmp_rle_carrier_positions(bytes(data[offset:]), 8)
    total_bits = len(payload) * 8
    if len(positions) < total_bits:
        raise ValueError("wbStego BMP RLE8 容量不足")
    bit_index = 0
    for byte in payload:
        for bit in range(7, -1, -1):
            pos = offset + positions[bit_index]
            data[pos] = (data[pos] & 0xFE) | ((byte >> bit) & 1)
            bit_index += 1


def _extract_rle8_lsb(data: bytearray, offset: int, capacity: int) -> bytes:
    positions = _bmp_rle_carrier_positions(bytes(data[offset:]), 8)
    out = bytearray()
    bit_pos = 0
    for _ in range(capacity):
        value = 0
        for bit in range(7, -1, -1):
            value |= (data[offset + positions[bit_pos]] & 1) << bit
            bit_pos += 1
        out.append(value)
    return bytes(out)


def _embed_rle4_nibble_lsb(data: bytearray, offset: int, payload: bytes) -> None:
    positions = _bmp_rle_carrier_positions(bytes(data[offset:]), 4)
    if len(positions) * 2 < len(payload) * 8:
        raise ValueError("wbStego BMP RLE4 容量不足")
    pos_index = 0
    for byte in payload:
        for pair in range(3, -1, -1):
            pos = offset + positions[pos_index]
            high = (byte >> (2 * pair + 1)) & 1
            low = (byte >> (2 * pair)) & 1
            data[pos] = (data[pos] & 0xEE) | (high << 4) | low
            pos_index += 1


def _extract_rle4_nibble_lsb(data: bytearray, offset: int, capacity: int) -> bytes:
    positions = _bmp_rle_carrier_positions(bytes(data[offset:]), 4)
    out = bytearray()
    pos_index = 0
    for _ in range(capacity):
        value = 0
        for pair in range(3, -1, -1):
            pos = offset + positions[pos_index]
            value |= ((data[pos] & 0x10) >> 4) << (2 * pair + 1)
            value |= (data[pos] & 1) << (2 * pair)
            pos_index += 1
        out.append(value)
    return bytes(out)


def _extension3(path: Path) -> str:
    suffix = path.suffix[1:]
    if not suffix:
        return "///"
    if len(suffix) >= 3:
        return suffix[:3]
    return suffix + "/" * (3 - len(suffix))


def _prepend_ext(extension: str, payload: bytes) -> bytes:
    return extension.encode("latin1", errors="replace")[:3].ljust(3, b"/") + payload


def _prepend_size(payload: bytes, size: int) -> bytes:
    if size > 0xFFFFFF:
        raise ValueError("wbStego 长度字段最大支持 16777215 字节")
    return bytes((size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF)) + payload


def _read_size24(data: bytes) -> int:
    return data[0] | (data[1] << 8) | (data[2] << 16)


def _distribute(payload_without_outer_size: bytes, avail_size: int) -> bytes:
    size = len(payload_without_outer_size)
    spacing = (avail_size / (size + 5)) - 1
    data = payload_without_outer_size
    if spacing > 0:
        out = bytearray()
        error = 0.0
        filler = 0
        for byte in data:
            out.append(byte)
            error += spacing
            if error >= 1:
                int_space = math.trunc(error)
                for _ in range(int_space):
                    out.append(filler & 0xFF)
                    filler = (filler + 73) & 0xFF
                    error -= 1
        data = bytes(out)
        data = _prepend_size(data, size)
    return _prepend_size(data, len(data))


def _undistribute(data_with_inner_size: bytes, avail_size: int) -> bytes:
    if len(data_with_inner_size) < 3:
        return data_with_inner_size
    real_size = _read_size24(data_with_inner_size[:3])
    spacing = (avail_size / (real_size + 5)) - 1
    if spacing <= 0:
        return data_with_inner_size[3:]
    out = bytearray()
    error = 0.0
    for byte in data_with_inner_size[3:]:
        if error < 1:
            out.append(byte)
            error += spacing
            if len(out) == real_size:
                break
        else:
            error -= 1
    return bytes(out)


def _is_distributed(data_with_inner_size: bytes, avail_size: int) -> bool:
    if len(data_with_inner_size) < 3:
        return False
    fullsize = len(data_with_inner_size)
    size = _read_size24(data_with_inner_size[:3]) + 5
    if size >= fullsize:
        return False
    spacing = (avail_size / (size + 5)) - 1
    if spacing <= 0:
        return False
    spacing += 1
    return spacing * size > fullsize - 3


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")


def hide_wbstego(
    input_path: Path,
    output_path: Path,
    payload_path: Path,
    *,
    carrier: str = "auto",
    distribute: bool = False,
    password: str | None = None,
    crypt: bool = True,
    mix: bool = False,
    transmit_password: bool = False,
) -> WbStegoResult:
    resolved = _resolve_carrier(input_path, carrier)
    if resolved == "bmp":
        return hide_wbstego_bmp(
            input_path,
            output_path,
            payload_path,
            distribute=distribute,
            password=password,
            crypt=crypt,
            mix=mix,
            transmit_password=transmit_password,
        )
    _check_file(input_path, "载体文件")
    _check_file(payload_path, "载荷文件")
    data = input_path.read_bytes()
    capacity = _text_capacity(data, resolved)
    extension = _extension3(payload_path)
    payload = _prepend_ext(extension, payload_path.read_bytes())
    if password is not None:
        payload = _encrypt_wbstego_payload(
            payload,
            password,
            crypt=crypt,
            mix=mix,
            transmit_password=transmit_password,
        )
    if distribute:
        payload = _distribute(payload, capacity)
    else:
        payload = _prepend_size(payload, len(payload))
    if len(payload) > capacity:
        raise ValueError(f"wbStego {resolved.upper()} 容量不足：需要 {len(payload)} bytes，可用 {capacity} bytes")
    if resolved == "asc":
        out = _ascii_replace_embed(data, payload)
    elif resolved in {"txt", "html"}:
        out = _line_insert_embed(data, payload)
    elif resolved == "pdf":
        out = _pdf_insert_embed(data, payload)
    else:
        raise ValueError(f"未知 wbStego 载体：{resolved}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(out)
    return WbStegoResult(
        operation="image.wbstego.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format=resolved.upper(),
        bit_count=0,
        compression=0,
        capacity_bytes=capacity,
        payload_bytes=payload_path.stat().st_size,
        written_bytes=output_path.stat().st_size,
        embedded_extension=extension.replace("/", ""),
        distributed=distribute,
        password_protected=password is not None,
    )


def extract_wbstego(input_path: Path, output_path: Path, *, carrier: str = "auto", password: str | None = None) -> WbStegoResult:
    resolved = _resolve_carrier(input_path, carrier)
    if resolved == "bmp":
        return extract_wbstego_bmp(input_path, output_path, password=password)
    _check_file(input_path, "载体文件")
    data = input_path.read_bytes()
    capacity = _text_capacity(data, resolved)
    if resolved == "asc":
        stream = _ascii_replace_extract(data)
    elif resolved in {"txt", "html"}:
        stream = _line_insert_extract(data)
    elif resolved == "pdf":
        stream = _pdf_insert_extract(data)
    else:
        raise ValueError(f"未知 wbStego 载体：{resolved}")
    payload, extension, distributed, password_verified = _decode_wbstego_payload(stream, capacity, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return WbStegoResult(
        operation="image.wbstego.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format=resolved.upper(),
        bit_count=0,
        compression=0,
        capacity_bytes=capacity,
        payload_bytes=len(payload),
        written_bytes=len(payload),
        embedded_extension=extension,
        distributed=distributed,
        password_protected=password is not None,
        password_verified=password_verified,
    )


def analyse_wbstego(input_path: Path, *, carrier: str = "auto") -> WbStegoResult:
    resolved = _resolve_carrier(input_path, carrier)
    if resolved == "bmp":
        return analyse_wbstego_bmp(input_path)
    _check_file(input_path, "载体文件")
    capacity = _text_capacity(input_path.read_bytes(), resolved)
    return WbStegoResult(
        operation="image.wbstego.analyse",
        input_path=str(input_path),
        output_path="",
        output_paths=[],
        carrier_format=resolved.upper(),
        bit_count=0,
        compression=0,
        capacity_bytes=capacity,
    )


def _resolve_carrier(path: Path, carrier: str) -> str:
    value = carrier.lower()
    if value != "auto":
        aliases = {"htm": "html", "text": "txt", "ascii": "asc"}
        value = aliases.get(value, value)
        if value in {"bmp", "asc", "txt", "html", "pdf"}:
            return value
        raise ValueError("carrier 必须是 auto、bmp、asc、txt、html 或 pdf")
    suffix = path.suffix.lower().lstrip(".")
    if suffix == "bmp":
        return "bmp"
    if suffix == "pdf":
        return "pdf"
    if suffix in {"htm", "html"}:
        return "html"
    return "txt"


def _text_capacity(data: bytes, carrier: str) -> int:
    if carrier == "asc":
        return sum(1 for byte in data if byte in {0, 0x20}) // 8
    if carrier in {"txt", "html"}:
        return len(_line_break_positions(data))
    if carrier == "pdf":
        return len(_pdf_cr_positions(data))
    raise ValueError(f"未知 wbStego 载体：{carrier}")


def _decode_wbstego_payload(
    stream: bytes, capacity: int, *, password: str | None = None
) -> tuple[bytes, str, bool, bool]:
    if len(stream) < 3:
        raise ValueError("wbStego 数据不足，缺少长度字段")
    stored_size = _read_size24(stream[:3])
    if stored_size > len(stream) - 3:
        raise ValueError(f"wbStego 长度异常：{stored_size} > {len(stream) - 3}")
    data = bytes(stream[3 : 3 + stored_size])
    distributed = _is_distributed(data, capacity)
    if distributed:
        data = _undistribute(data, capacity)
    password_verified = False
    if password is not None:
        data, password_verified = _decrypt_wbstego_payload(data, password)
    if len(data) < 3:
        raise ValueError("wbStego 数据缺少 3 字符扩展名")
    extension = data[:3].decode("latin1", errors="replace").replace("/", "")
    return data[3:], extension, distributed, password_verified


def brute_wbstego(
    input_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    carrier: str = "auto",
    contains: bytes | None = None,
    prefix: bytes | None = None,
    include_default: bool = True,
) -> WbStegoResult:
    _check_file(wordlist_path, "字典文件")
    candidates: list[str] = []
    if include_default:
        candidates.append("")
    candidates.extend(
        line.rstrip("\r\n")
        for line in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    )
    seen: set[str] = set()
    attempts = 0
    with tempfile.TemporaryDirectory() as directory:
        trial_output = Path(directory) / "trial.bin"
        for password in candidates:
            if password in seen:
                continue
            seen.add(password)
            attempts += 1
            result: WbStegoResult | None
            try:
                result = extract_wbstego(
                    input_path,
                    trial_output,
                    carrier=carrier,
                    password=password,
                )
            except (ValueError, OSError, UnicodeError, IndexError, ZeroDivisionError):
                result = None
            if result is None:
                continue
            payload = trial_output.read_bytes()
            if not _wbstego_payload_matches(
                payload,
                contains=contains,
                prefix=prefix,
                password_verified=result.password_verified,
            ):
                continue
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(payload)
            return WbStegoResult(
                operation="image.wbstego.brute",
                input_path=str(input_path),
                output_path=str(output_path),
                output_paths=[str(output_path)],
                carrier_format=result.carrier_format,
                bit_count=result.bit_count,
                compression=result.compression,
                capacity_bytes=result.capacity_bytes,
                payload_bytes=len(payload),
                written_bytes=len(payload),
                embedded_extension=result.embedded_extension,
                distributed=result.distributed,
                password_protected=True,
                password_verified=result.password_verified,
                found_password=password,
                attempts=attempts,
            )
    raise ValueError(f"字典未命中 wbStego 密码，尝试 {attempts} 个候选")


def _wbstego_payload_matches(
    payload: bytes,
    *,
    contains: bytes | None,
    prefix: bytes | None,
    password_verified: bool,
) -> bool:
    if contains is not None and contains not in payload:
        return False
    if prefix is not None and not payload.startswith(prefix):
        return False
    if contains is None and prefix is None:
        return password_verified
    return True


def _encrypt_wbstego_payload(
    data: bytes,
    password: str,
    *,
    crypt: bool,
    mix: bool,
    transmit_password: bool,
) -> bytes:
    password_bytes = _password_bytes(password)
    control = 0
    if mix:
        control |= 0x40
    if crypt:
        control |= 0x80
    parity = _password_parity(password_bytes)
    transmit_parity = parity if transmit_password else not parity
    if transmit_parity:
        control |= 0x01
    out = data
    if transmit_password:
        out = _mix_password(out, password_bytes)
    if mix:
        out = _mix_data(out, password_bytes)
    if crypt:
        out = _crypt_data(out, password_bytes)
    return bytes([control]) + out


def _decrypt_wbstego_payload(data: bytes, password: str) -> tuple[bytes, bool]:
    if not data:
        raise ValueError("wbStego 密码数据缺少控制字节")
    password_bytes = _password_bytes(password)
    control = data[0]
    out = data[1:]
    if control & 0x80:
        out = _crypt_data(out, password_bytes)
    if control & 0x40:
        out = _unmix_data(out, password_bytes)
    password_verified = False
    if _control_transmit_matches(control, password_bytes):
        out, extracted_password = _extract_password(out, password_bytes)
        password_verified = extracted_password == password_bytes
        if not password_verified:
            raise ValueError("wbStego 密码校验失败")
    return out, password_verified


def _password_bytes(password: str) -> bytes:
    data = password.encode("latin1", errors="replace")
    if not data:
        raise ValueError("wbStego 密码模式需要非空密码")
    return data


def _password_parity(password: bytes) -> bool:
    odd = False
    for byte in password:
        if byte & 1:
            odd = not odd
    return odd


def _control_transmit_matches(control: int, password: bytes) -> bool:
    return bool(control & 1) == _password_parity(password)


def _mix_password(data: bytes, password: bytes) -> bytes:
    out = bytearray()
    pwd_index = 0
    offset = password[pwd_index] & 0x3F
    pos = 0
    while True:
        chunk = data[pos : pos + offset]
        out.extend(chunk)
        pos += len(chunk)
        if len(chunk) != offset:
            break
        if offset < 64:
            out.append(password[pwd_index])
            if pwd_index < len(password) - 1:
                pwd_index += 1
                offset = password[pwd_index] & 0x3F
            else:
                offset = 1024
    return bytes(out)


def _extract_password(data: bytes, password: bytes) -> tuple[bytes, bytes]:
    out = bytearray()
    extracted = bytearray()
    pwd_index = 0
    offset = password[pwd_index] & 0x3F
    pos = 0
    while True:
        chunk = data[pos : pos + offset]
        out.extend(chunk)
        pos += len(chunk)
        if len(chunk) != offset:
            break
        if offset < 64 and pos < len(data):
            extracted.append(data[pos])
            pos += 1
        if offset < 64:
            if pwd_index < len(password) - 1:
                pwd_index += 1
                offset = password[pwd_index] & 0x3F
            else:
                offset = 1024
    pwdleft = max(0, len(password) - len(extracted))
    if pwdleft:
        tail = bytes(out[-pwdleft:])
        extracted.extend(tail)
        del out[-pwdleft:]
    return bytes(out), bytes(extracted)


def _mix_data(data: bytes, password: bytes) -> bytes:
    out = bytearray()
    length = len(password)
    left = 0
    right = length - 1
    m = password[left] & 0x0F
    n = password[right] & 0x0F
    pos = 0
    while True:
        asked = (m + 1) * (n + 1)
        block = bytearray(data[pos : pos + asked])
        pos += len(block)
        if len(block) < asked:
            add = password[0]
            out.extend(((byte + add) & 0xFF) for byte in block)
            break
        matrix = [[0 for _ in range(n + 1)] for _ in range(m + 1)]
        for i in range(m + 1):
            for j in range(n + 1):
                matrix[i][j] = block[i * (n + 1) + j]
        mixed = bytearray()
        for j in range(n + 1):
            for i in range(m, -1, -1):
                mixed.append(matrix[i][j])
        out.extend(mixed)
        left, right = _next_mix_indices(length, left, right)
        m = password[left] & 0x0F
        n = password[right] & 0x0F
    return bytes(out)


def _unmix_data(data: bytes, password: bytes) -> bytes:
    out = bytearray()
    length = len(password)
    left = 0
    right = length - 1
    m = password[left] & 0x0F
    n = password[right] & 0x0F
    pos = 0
    while True:
        asked = (m + 1) * (n + 1)
        block = bytearray(data[pos : pos + asked])
        pos += len(block)
        if not block:
            break
        if len(block) == asked:
            matrix = [[0 for _ in range(n + 1)] for _ in range(m + 1)]
            idx = 0
            for j in range(n + 1):
                for i in range(m, -1, -1):
                    matrix[i][j] = block[idx]
                    idx += 1
            unmixed = bytearray()
            for i in range(m + 1):
                for j in range(n + 1):
                    unmixed.append(matrix[i][j])
            out.extend(unmixed)
            left, right = _next_mix_indices(length, left, right)
            m = password[left] & 0x0F
            n = password[right] & 0x0F
        else:
            sub = password[0]
            out.extend(((byte - sub) & 0xFF) for byte in block)
            break
    return bytes(out)


def _next_mix_indices(length: int, left: int, right: int) -> tuple[int, int]:
    half = length // 2
    if left < half - 1 or (length % 2 == 1 and left == half - 1):
        left += 1
    else:
        left = 0
    if right > half or (length % 2 == 1 and right == half):
        right -= 1
    else:
        right = length - 1
    return left, right


def _crypt_data(data: bytes, password: bytes) -> bytes:
    gen = _MLKBBSGenerator(password)
    return bytes(byte ^ gen.next_value() for byte in data)


class _MLKBBSGenerator:
    def __init__(self, password: bytes) -> None:
        length = len(password)
        leaveout = [[False for _ in range(8)] for _ in range(length)]
        self.m = 0
        self.p = 0
        self.q = 0
        if length >= 32:
            for i in range(length):
                for j in range(1, 8):
                    leaveout[i][j] = True
            no_left = length - 32
            if no_left > 0:
                for i in range(1, no_left + 1):
                    j = round(i * math.trunc(length / no_left))
                    if 1 <= j <= length:
                        leaveout[j - 1][0] = True
        elif length >= 4:
            row_left = round(8 - math.trunc(32 / length))
            if length not in {4, 8, 16}:
                row_left -= 1
            row_left = 8 - row_left
            if row_left < 7:
                for i in range(length):
                    for j in range(7, row_left - 1, -1):
                        leaveout[i][j] = True
            no_left = length - ((32 % length) * row_left)
            if no_left > 0:
                for i in range(1, no_left + 1):
                    j = round(i * math.trunc(length / no_left))
                    if 1 <= j <= length and 0 <= row_left < 8:
                        leaveout[j - 1][row_left] = True
        else:
            no_left = 32 - (length * 8)
            for i in range(31 - no_left, 32):
                self.m = _set_bit32(self.m, i, True)
        digit = 0
        for i in range(length - 1, -1, -1):
            for j in range(8):
                if not leaveout[i][j]:
                    self.m = _set_bit32(self.m, digit, bool(password[i] & (1 << j)))
                    digit += 1
        digit = 0
        for i in range(31, -1, -1):
            if i % 2:
                self.p = _set_bit32(self.p, digit, _get_bit32(self.m, i))
            else:
                self.q = _set_bit32(self.q, digit, _get_bit32(self.m, i))
                digit += 1
        self.m = _set_bit32(self.m, 31, False)
        self.p = self.p + (3 - (self.p % 4))
        self.q = self.q + (3 - (self.q % 4))
        self.z = self.m + (0 - (self.m % 4))
        self.n = self.p * self.q

    def next_value(self) -> int:
        self.z = (self.z * self.z) % self.n if self.n else 0
        out = 0
        if _get_bit32(self.z, 13) ^ _get_bit32(self.m, 7):
            out |= 0x01
        if _get_bit32(self.z, 31):
            out |= 0x02
        if _get_bit32(self.z, 10) and _get_bit32(self.m, 30):
            out |= 0x04
        if _get_bit32(self.z, 23) or (_get_bit32(self.m, 19) ^ _get_bit32(self.m, 19)):
            out |= 0x08
        if (_get_bit32(self.z, 17) and _get_bit32(self.z, 27)) ^ _get_bit32(self.m, 16):
            out |= 0x10
        if _get_bit32(self.m, 13):
            out |= 0x20
        if _get_bit32(self.z, 20) ^ _get_bit32(self.m, 25):
            out |= 0x40
        if _get_bit32(self.z, 26):
            out |= 0x80
        return out


def _set_bit32(value: int, digit: int, set_to: bool) -> int:
    if set_to:
        return (value | (1 << digit)) & 0xFFFFFFFF
    return (value & ~(1 << digit)) & 0xFFFFFFFF


def _get_bit32(value: int, digit: int) -> bool:
    return bool(value & (1 << digit))


def _byte_to_space_tab(byte: int) -> bytes:
    return bytes(0x09 if (byte & (1 << bit)) else 0x20 for bit in range(7, -1, -1))


def _space_tab_to_byte(chunk: bytes) -> int:
    value = 0
    for bit, byte in zip(range(7, -1, -1), chunk, strict=False):
        if byte == 0x09:
            value |= 1 << bit
    return value


def _line_break_positions(data: bytes) -> list[int]:
    positions: list[int] = []
    last_cr = False
    for index, byte in enumerate(data):
        if byte in {0x0D, 0x0A}:
            if not last_cr:
                positions.append(index)
                if byte == 0x0D:
                    last_cr = True
            else:
                last_cr = False
        else:
            last_cr = False
    return positions


def _line_insert_embed(data: bytes, payload: bytes) -> bytes:
    positions = set(_line_break_positions(data))
    payload_index = 0
    out = bytearray()
    for index, byte in enumerate(data):
        if index in positions and payload_index < len(payload):
            out.extend(_byte_to_space_tab(payload[payload_index]))
            payload_index += 1
        out.append(byte)
    if payload_index < len(payload):
        raise ValueError("wbStego TXT/HTML 容量不足")
    return bytes(out)


def _line_insert_extract(data: bytes) -> bytes:
    out = bytearray()
    for pos in _line_break_positions(data):
        if pos >= 8:
            out.append(_space_tab_to_byte(data[pos - 8 : pos]))
    return bytes(out)


def _ascii_replace_embed(data: bytes, payload: bytes) -> bytes:
    bits = ((byte >> bit) & 1 for byte in payload for bit in range(7, -1, -1))
    out = bytearray(data)
    embedded = 0
    total_bits = len(payload) * 8
    for index, byte in enumerate(out):
        if byte not in {0, 0x20}:
            continue
        if embedded >= total_bits:
            break
        out[index] = 0x20 if next(bits) else 0
        embedded += 1
    if embedded < total_bits:
        raise ValueError("wbStego ASC 容量不足")
    return bytes(out)


def _ascii_replace_extract(data: bytes) -> bytes:
    bits = [1 if byte == 0x20 else 0 for byte in data if byte in {0, 0x20}]
    out = bytearray()
    for index in range(0, len(bits) - 7, 8):
        value = 0
        for bit in range(7, -1, -1):
            value |= bits[index + (7 - bit)] << bit
        out.append(value)
    return bytes(out)


def _pdf_cr_positions(data: bytes) -> list[int]:
    positions: list[int] = []
    in_object = False
    tag = ""
    for index, byte in enumerate(data):
        if not in_object:
            if byte == 0x0D:
                positions.append(index)
                tag = ""
                continue
            tag = _pdf_tag_step(tag, byte, "obj")
            if tag == "obj":
                in_object = True
                tag = ""
        else:
            tag = _pdf_tag_step(tag, byte, "endobj")
            if tag == "endobj":
                in_object = False
                tag = ""
    return positions


def _pdf_tag_step(current: str, byte: int, target: str) -> str:
    expected_index = len(current)
    if expected_index >= len(target):
        return ""
    if byte in {ord(target[expected_index]), ord(target[expected_index].upper())}:
        return current + target[expected_index]
    return ""



def _pdf_insert_embed(data: bytes, payload: bytes) -> bytes:
    positions = set(_pdf_cr_positions(data))
    payload_index = 0
    out = bytearray()
    for index, byte in enumerate(data):
        if index in positions and payload_index < len(payload):
            out.extend(_byte_to_space_tab(payload[payload_index]))
            payload_index += 1
        out.append(byte)
    if payload_index < len(payload):
        raise ValueError("wbStego PDF 容量不足")
    return bytes(out)


def _pdf_insert_extract(data: bytes) -> bytes:
    out = bytearray()
    for pos in _pdf_cr_positions(data):
        if pos >= 8:
            out.append(_space_tab_to_byte(data[pos - 8 : pos]))
    return bytes(out)
