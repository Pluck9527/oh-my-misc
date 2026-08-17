from __future__ import annotations

import hashlib
import hmac
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

TAB_WIDTH = 8
SNOW_PROTECTED_MAGIC = b"OMMSNOW\x01"
SNOW_FLAG_COMPRESSED = 0x01
SNOW_FLAG_ENCRYPTED = 0x02
SNOW_SALT_BYTES = 16
SNOW_MAC_BYTES = 16


@dataclass(frozen=True)
class SnowResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    tool_path: str
    backend: str
    line_length: int
    password_used: bool = False
    compressed: bool = False
    payload_bytes: int = 0
    written_bytes: int = 0
    capacity_bits_low: int = 0
    capacity_bits_high: int = 0
    extra_lines: int = 0
    stdout: str = ""
    stderr: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def hide_snow(
    input_path: Path,
    output_path: Path,
    *,
    payload_path: Path | None = None,
    text: str | None = None,
    password: str | None = None,
    compress: bool = False,
    line_length: int = 80,
    backend: str = "auto",
    snow_path: Path | None = None,
) -> SnowResult:
    """Conceal a message with the native SNOW trailing whitespace backend."""

    _check_file(input_path, "载体文本")
    payload = _load_payload(payload_path=payload_path, text=text)
    _validate_backend(backend)
    _validate_line_length(line_length)
    _ = snow_path
    packed = _pack_snow_payload(payload, password=password, compress=compress)
    stego, capacity_low, capacity_high, extra_lines = conceal_snow_native(
        input_path.read_bytes(), packed, line_length=line_length
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(stego)
    return SnowResult(
        operation="text.snow.hide-native",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        backend="native",
        line_length=line_length,
        password_used=password is not None,
        compressed=compress,
        payload_bytes=len(payload),
        written_bytes=len(stego),
        capacity_bits_low=capacity_low,
        capacity_bits_high=capacity_high,
        extra_lines=extra_lines,
    )


def extract_snow(
    input_path: Path,
    output_path: Path,
    *,
    password: str | None = None,
    compress: bool = False,
    backend: str = "auto",
    snow_path: Path | None = None,
) -> SnowResult:
    """Extract a message with the native SNOW trailing whitespace backend."""

    _check_file(input_path, "SNOW 文本")
    _validate_backend(backend)
    _ = snow_path
    raw = extract_snow_native(input_path.read_bytes())
    payload = _unpack_snow_payload(raw, password=password, compress=compress)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return SnowResult(
        operation="text.snow.extract-native",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        backend="native",
        line_length=0,
        password_used=password is not None,
        compressed=compress,
        payload_bytes=len(payload),
        written_bytes=len(payload),
    )


def capacity_snow(input_path: Path, *, line_length: int = 80) -> SnowResult:
    _check_file(input_path, "载体文本")
    _validate_line_length(line_length)
    low, high = snow_capacity_bits(input_path.read_bytes(), line_length=line_length)
    return SnowResult(
        operation="text.snow.capacity",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        tool_path="python",
        backend="native",
        line_length=line_length,
        capacity_bits_low=low,
        capacity_bits_high=high,
    )


def conceal_snow_native(
    cover: bytes, payload: bytes, *, line_length: int = 80
) -> tuple[bytes, int, int, int]:
    lines = _normalised_lines(cover)
    writer = _SnowWhitespaceWriter(lines, line_length=line_length)
    bit_count = 0
    value = 0
    for byte in payload:
        for bit_index in range(7, -1, -1):
            bit = (byte >> bit_index) & 1
            value = (value << 1) | bit
            bit_count += 1
            if bit_count == 3:
                writer.write_value(value)
                value = 0
                bit_count = 0
    if bit_count:
        while bit_count < 3:
            value <<= 1
            bit_count += 1
        writer.write_value(value)
    output = writer.flush()
    low, high = snow_capacity_bits(cover, line_length=line_length)
    return output, low, high, writer.extra_lines


def extract_snow_native(data: bytes) -> bytes:
    bits: list[int] = []
    start_tab_found = False
    for line in data.splitlines():
        line = line.rstrip(b"\r")
        start = _trailing_whitespace_start(line)
        if start is None:
            continue
        trailing = line[start:]
        if not start_tab_found and trailing.startswith(b" "):
            continue
        if not start_tab_found and trailing.startswith(b"\t"):
            start_tab_found = True
            trailing = trailing[1:]
            if not trailing:
                continue
        if start_tab_found:
            bits.extend(_decode_whitespace_bits(trailing))
    return _bits_to_bytes(bits)


def snow_capacity_bits(data: bytes, *, line_length: int = 80) -> tuple[int, int]:
    low = 0
    high = 0
    for line in _normalised_lines(data):
        add_low, add_high = _line_storage(line, line_length=line_length)
        low += add_low
        high += add_high
    if low > 0:
        low -= 1
        high -= 1
    return low, high


class _SnowWhitespaceWriter:
    def __init__(self, lines: list[bytes], *, line_length: int):
        self.lines = lines
        self.line_length = line_length
        self.index = 0
        self.buffer = b""
        self.column = 0
        self.loaded = False
        self.first_tab = False
        self.needs_tab = False
        self.output: list[bytes] = []
        self.extra_lines = 0

    def write_value(self, value: int) -> None:
        if not self.loaded:
            self._load()
        if not self.first_tab:
            while _tabpos(self.column) >= self.line_length:
                self._flush_line()
                self._load()
            self.buffer += b"\t"
            self.column = _tabpos(self.column)
            self.first_tab = True
        nspaces = ((value & 1) << 2) | (value & 2) | ((value & 4) >> 2)
        while not self._append_whitespace(nspaces):
            self._flush_line()
            self._load()

    def flush(self) -> bytes:
        if self.loaded:
            self._flush_line()
            self.loaded = False
        while self.index < len(self.lines):
            self.output.append(self.lines[self.index] + b"\n")
            self.index += 1
        return b"".join(self.output)

    def _load(self) -> None:
        if self.index < len(self.lines):
            self.buffer = self.lines[self.index]
            self.index += 1
        else:
            self.buffer = b""
            self.extra_lines += 1
        self.column = _visual_column(self.buffer)
        self.loaded = True
        self.needs_tab = False

    def _flush_line(self) -> None:
        self.output.append(self.buffer + b"\n")
        self.loaded = False
        self.buffer = b""
        self.column = 0

    def _append_whitespace(self, nspaces: int) -> bool:
        column = self.column
        if self.needs_tab:
            column = _tabpos(column)
        if nspaces == 0:
            column = _tabpos(column)
        else:
            column += nspaces
        if column >= self.line_length:
            return False
        if self.needs_tab:
            self.buffer += b"\t"
            self.column = _tabpos(self.column)
        if nspaces == 0:
            self.buffer += b"\t"
            self.column = _tabpos(self.column)
            self.needs_tab = False
        else:
            self.buffer += b" " * nspaces
            self.column += nspaces
            self.needs_tab = True
        return True


def _normalised_lines(data: bytes) -> list[bytes]:
    return [line.rstrip(b" \t\r") for line in data.splitlines()]


def _trailing_whitespace_start(line: bytes) -> int | None:
    index = len(line) - 1
    while index >= 0 and line[index] in (0x20, 0x09):
        index -= 1
    if index == len(line) - 1:
        return None
    return index + 1


def _decode_whitespace_bits(trailing: bytes) -> list[int]:
    bits: list[int] = []
    spaces = 0
    for byte in trailing:
        if byte == 0x20:
            spaces += 1
        elif byte == 0x09:
            bits.extend(_bits_from_space_count(spaces))
            spaces = 0
    if spaces > 0:
        bits.extend(_bits_from_space_count(spaces))
    return bits


def _bits_from_space_count(count: int) -> list[int]:
    if count > 7:
        raise ValueError(f"非法 SNOW 空格计数：{count}")
    return [count & 1, (count >> 1) & 1, (count >> 2) & 1]


def _bits_to_bytes(bits: list[int]) -> bytes:
    output = bytearray()
    value = 0
    count = 0
    for bit in bits:
        value = (value << 1) | bit
        count += 1
        if count == 8:
            output.append(value)
            value = 0
            count = 0
    return bytes(output)


def _line_storage(line: bytes, *, line_length: int) -> tuple[int, int]:
    length = _visual_column(line)
    low = 0
    high = 0
    if length > line_length - 2:
        return 0, 0
    if length // TAB_WIDTH == line_length // TAB_WIDTH:
        high += 3
        return low, high
    if length & 7:
        high += 3
        length = _tabpos(length)
    if line_length & 7:
        high += 3
    nbits = ((line_length - length) // TAB_WIDTH) * 3
    low += nbits
    high += nbits
    return low, high


def _visual_column(line: bytes) -> int:
    column = 0
    for byte in line:
        if byte == 0x09:
            column = _tabpos(column)
        else:
            column += 1
    return column


def _tabpos(column: int) -> int:
    return (column + TAB_WIDTH) & ~(TAB_WIDTH - 1)


def _load_payload(*, payload_path: Path | None, text: str | None) -> bytes:
    if payload_path is None and text is None:
        raise ValueError("snow hide 需要 --payload 或 --text")
    if payload_path is not None and text is not None:
        raise ValueError("snow hide 只能指定 --payload 或 --text 之一")
    if payload_path is not None:
        _check_file(payload_path, "载荷文件")
        return payload_path.read_bytes()
    assert text is not None
    return text.encode("utf-8")


def _pack_snow_payload(payload: bytes, *, password: str | None, compress: bool) -> bytes:
    flags = 0
    body = payload
    if compress:
        body = zlib.compress(body, level=9)
        flags |= SNOW_FLAG_COMPRESSED
    if password is not None:
        salt = hashlib.sha256(
            b"oh-my-misc:text-snow:salt\x00" + password.encode("utf-8") + payload
        ).digest()[:SNOW_SALT_BYTES]
        body = _snow_crypt(body, password=password, salt=salt)
        flags |= SNOW_FLAG_ENCRYPTED
        mac = _snow_mac(flags, salt, body, password=password)
    elif compress:
        salt = b"\x00" * SNOW_SALT_BYTES
        mac = b"\x00" * SNOW_MAC_BYTES
    else:
        return payload
    return (
        SNOW_PROTECTED_MAGIC
        + bytes([flags])
        + len(payload).to_bytes(8, "big")
        + salt
        + mac
        + body
    )


def _unpack_snow_payload(raw: bytes, *, password: str | None, compress: bool) -> bytes:
    _ = compress
    if not raw.startswith(SNOW_PROTECTED_MAGIC):
        return raw
    header_size = 8 + 1 + 8 + SNOW_SALT_BYTES + SNOW_MAC_BYTES
    if len(raw) < header_size:
        raise ValueError("SNOW protected payload 头部不完整")
    flags = raw[8]
    expected_size = int.from_bytes(raw[9:17], "big")
    salt = raw[17 : 17 + SNOW_SALT_BYTES]
    mac_start = 17 + SNOW_SALT_BYTES
    stored_mac = raw[mac_start : mac_start + SNOW_MAC_BYTES]
    body = raw[mac_start + SNOW_MAC_BYTES :]
    if flags & ~(SNOW_FLAG_COMPRESSED | SNOW_FLAG_ENCRYPTED):
        raise ValueError(f"SNOW protected payload 标志位异常：0x{flags:02x}")
    if flags & SNOW_FLAG_ENCRYPTED:
        if password is None:
            raise ValueError("SNOW protected payload 需要 password")
        expected_mac = _snow_mac(flags, salt, body, password=password)
        if not hmac.compare_digest(stored_mac, expected_mac):
            raise ValueError("SNOW protected payload password 校验失败")
        body = _snow_crypt(body, password=password, salt=salt)
    if flags & SNOW_FLAG_COMPRESSED:
        body = zlib.decompress(body)
    if len(body) != expected_size:
        raise ValueError(f"SNOW protected payload 长度异常：{len(body)} != {expected_size}")
    return body


def _snow_crypt(data: bytes, *, password: str, salt: bytes) -> bytes:
    key = hashlib.sha256(b"oh-my-misc:text-snow:key\x00" + salt + password.encode("utf-8")).digest()
    output = bytearray()
    counter = 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(byte ^ stream for byte, stream in zip(data, output, strict=False))


def _snow_mac(flags: int, salt: bytes, body: bytes, *, password: str) -> bytes:
    key = hashlib.sha256(b"oh-my-misc:text-snow:mac\x00" + salt + password.encode("utf-8")).digest()
    return hmac.new(key, bytes([flags]) + salt + body, hashlib.sha256).digest()[:SNOW_MAC_BYTES]


def _validate_backend(backend: str) -> None:
    if backend not in {"auto", "native", "tool"}:
        raise ValueError("backend 必须是 auto、native 或 tool")


def _validate_line_length(line_length: int) -> None:
    if line_length < 8:
        raise ValueError("line_length 必须大于等于 8")


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
