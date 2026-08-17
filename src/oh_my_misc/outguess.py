from __future__ import annotations

import hashlib
import math
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class OutguessResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    tool_path: str
    key_used: bool
    backend: str = "native"
    found_key: str | None = None
    attempts: int = 0
    written_bytes: int = 0
    stdout: str = ""
    stderr: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def extract_outguess(
    input_path: Path,
    output_path: Path,
    *,
    key: str = "",
    outguess_path: Path | None = None,
    backend: str = "auto",
) -> OutguessResult:
    """Extract OutGuess data with the native Python backend."""

    _check_file(input_path, "JPEG/PNM 文件")
    if backend not in {"auto", "native", "tool"}:
        raise ValueError("backend 必须是 auto、native 或 tool")
    _ = outguess_path
    payload = extract_outguess_native(input_path, key=key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return OutguessResult(
        operation="image.outguess.extract-native",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        backend="native",
        key_used=bool(key),
        found_key=key,
        attempts=1,
        written_bytes=len(payload),
    )


def hide_outguess(
    input_path: Path,
    output_path: Path,
    payload_path: Path,
    *,
    key: str = "",
    outguess_path: Path | None = None,
    backend: str = "auto",
) -> OutguessResult:
    """Embed OutGuess data with the native Python backend."""

    _check_file(input_path, "JPEG/PNM 文件")
    _check_file(payload_path, "载荷文件")
    if backend not in {"auto", "native", "tool"}:
        raise ValueError("backend 必须是 auto、native 或 tool")
    _ = outguess_path
    result_bytes = hide_outguess_native(input_path, payload_path.read_bytes(), key=key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(result_bytes)
    return OutguessResult(
        operation="image.outguess.hide-native",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        backend="native",
        key_used=bool(key),
        found_key=key,
        attempts=1,
        written_bytes=len(result_bytes),
    )


def brute_outguess(
    input_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    outguess_path: Path | None = None,
    contains: bytes | None = None,
    prefix: bytes | None = None,
    include_empty: bool = True,
    backend: str = "auto",
) -> OutguessResult:
    """Try OutGuess keys from a dictionary and keep the first matching payload."""

    _check_file(input_path, "JPEG/PNM 文件")
    _check_file(wordlist_path, "字典")
    if backend not in {"auto", "native", "tool"}:
        raise ValueError("backend 必须是 auto、native 或 tool")
    _ = outguess_path
    attempts = 0
    last_error = ""
    for candidate in _key_candidates(wordlist_path, include_empty=include_empty):
        attempts += 1
        try:
            payload = extract_outguess_native(input_path, key=candidate)
        except ValueError as error:
            last_error = str(error)
            continue
        if contains is not None and contains not in payload:
            continue
        if prefix is not None and not payload.startswith(prefix):
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        return OutguessResult(
            operation="image.outguess.brute-native",
            input_path=str(input_path),
            output_path=str(output_path),
            output_paths=[str(output_path)],
            tool_path="python",
            backend="native",
            key_used=bool(candidate),
            found_key=candidate,
            attempts=attempts,
            written_bytes=len(payload),
        )
    extra = f"；最后错误：{last_error}" if last_error else ""
    raise ValueError(f"OutGuess 字典爆破失败，尝试 {attempts} 个密钥{extra}")


class _Arc4:
    def __init__(self, type_name: str, key: str | bytes):
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        digest = hashlib.md5(type_name.encode("ascii") + key_bytes).digest()
        self.s = list(range(256))
        self.i = 0
        self.j = 0
        self.addrandom(digest)

    def getbyte(self) -> int:
        self.i = (self.i + 1) & 0xFF
        si = self.s[self.i]
        self.j = (self.j + si) & 0xFF
        sj = self.s[self.j]
        self.s[self.i] = sj
        self.s[self.j] = si
        return self.s[(si + sj) & 0xFF]

    def getword(self) -> int:
        return (
            (self.getbyte() << 24)
            | (self.getbyte() << 16)
            | (self.getbyte() << 8)
            | self.getbyte()
        )

    def addrandom(self, data: bytes) -> None:
        self.i = (self.i - 1) & 0xFF
        for n in range(256):
            self.i = (self.i + 1) & 0xFF
            si = self.s[self.i]
            self.j = (self.j + si + data[n % len(data)]) & 0xFF
            self.s[self.i] = self.s[self.j]
            self.s[self.j] = si

    def clone(self) -> _Arc4:
        other = object.__new__(_Arc4)
        other.s = self.s.copy()
        other.i = self.i
        other.j = self.j
        return other


class _Iterator:
    def __init__(self, key: str | bytes):
        self.skipmod = 32
        self.as_ = _Arc4("Seeding", key)
        self.off = self.as_.getword() % self.skipmod

    def next(self) -> int:
        self.off += (self.as_.getword() % self.skipmod) + 1
        return self.off

    def seed(self, seed: int) -> None:
        self.as_.addrandom(bytes((seed & 0xFF, (seed >> 8) & 0xFF)))

    def adapt(self, bits: int, datalen: int) -> None:
        remaining = bits - self.off
        base = bits / 32
        if remaining > base:
            multiplier = 2.0
        else:
            multiplier = 2.0 - ((bits / 32) - remaining) / (bits / 32)
        self.skipmod = int(multiplier * remaining / (8 * datalen))
        self.skipmod = max(self.skipmod, 1)

    def clone(self) -> _Iterator:
        other = object.__new__(_Iterator)
        other.skipmod = self.skipmod
        other.as_ = self.as_.clone()
        other.off = self.off
        return other


def extract_outguess_native(input_path: Path, *, key: str = "") -> bytes:
    if _is_pnm(input_path):
        return extract_outguess_pnm(input_path, key=key)
    if _is_jpeg(input_path):
        return extract_outguess_jpeg(input_path, key=key)
    raise ValueError("OutGuess native backend 只支持 PNM/PPM/PGM 和 baseline JPEG")


def hide_outguess_native(input_path: Path, payload: bytes, *, key: str = "") -> bytes:
    if _is_pnm(input_path):
        return hide_outguess_pnm(input_path, payload, key=key)
    if _is_jpeg(input_path):
        return hide_outguess_jpeg(input_path, payload, key=key)
    raise ValueError("OutGuess native backend 只支持 PNM/PPM/PGM 和 baseline JPEG")


def extract_outguess_jpeg(input_path: Path, *, key: str = "") -> bytes:
    image = _read_jpeg_dct_image_for_outguess(input_path)
    bits = [value & 1 for value in _iter_outguess_jpeg_coefficients(image)]
    if not bits:
        raise ValueError("JPEG 中没有 OutGuess 可用 DCT 系数")
    return _extract_outguess_from_bits(bits, key=key)


def hide_outguess_jpeg(input_path: Path, payload: bytes, *, key: str = "") -> bytes:
    image = _read_jpeg_dct_image_for_outguess(input_path)
    positions = list(_iter_outguess_jpeg_positions(image))
    if not positions:
        raise ValueError("JPEG 中没有 OutGuess 可用 DCT 系数")
    if len(payload) > 0xFFFF:
        raise ValueError("OutGuess JPEG 载荷不能超过 65535 bytes")
    if len(positions) // (len(payload) * 8 if payload else 1) < 2:
        raise ValueError(f"OutGuess JPEG 容量不足：payload={len(payload)} bytes, bits={len(positions)}")
    values = [_jpeg_get_position(image, position) for position in positions]
    enc = _Arc4("Encryption", key)
    body_enc = enc.clone()
    encrypted_payload = _xor_arc4(payload, body_enc)
    base_iterator = _Iterator(key)
    best_seed = None
    best_score = None
    last_error = ""
    for seed in range(256):
        trial = values.copy()
        try:
            changed, bias = _embed_outguess_sequence(trial, encrypted_payload, key=key, seed=seed, base_iterator=base_iterator, base_enc=enc, write=False, setter=_jpeg_sequence_setter)
        except ValueError as error:
            last_error = str(error)
            continue
        score = changed + bias
        if best_score is None or score < best_score:
            best_seed = seed
            best_score = score
    if best_seed is None:
        raise ValueError(f"OutGuess JPEG 找不到可用 seed：{last_error}")
    _embed_outguess_sequence(values, encrypted_payload, key=key, seed=best_seed, base_iterator=base_iterator, base_enc=enc, write=True, setter=_jpeg_sequence_setter)
    for position, value in zip(positions, values, strict=True):
        _jpeg_set_position(image, position, value)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _write_jpeg_dct_image_for_outguess(image, tmp_path)
        return tmp_path.read_bytes()
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def _extract_outguess_from_bits(bits: list[int], *, key: str) -> bytes:
    enc = _Arc4("Encryption", key)
    body_enc = enc.clone()
    iterator = _Iterator(key)
    header_encrypted = bytes(_retrieve_byte(bits, iterator) for _ in range(4))
    header = _xor_arc4(header_encrypted, enc)
    seed = header[0] | (header[1] << 8)
    datalen = header[2] | (header[3] << 8)
    if datalen <= 0 or datalen > math.ceil(len(bits) / 8):
        raise ValueError(f"OutGuess 载荷长度越界：{datalen}")
    iterator.seed(seed)
    encrypted = bytearray()
    remaining = datalen
    while remaining > 0:
        iterator.adapt(len(bits), remaining)
        encrypted.append(_retrieve_byte(bits, iterator))
        remaining -= 1
    return _xor_arc4(bytes(encrypted), body_enc)


def _embed_outguess_sequence(values: list[int], encrypted_payload: bytes, *, key: str, seed: int, base_iterator: _Iterator, base_enc: _Arc4, write: bool, setter) -> tuple[int, int]:
    bits_count = len(values)
    iterator = base_iterator.clone()
    enc = base_enc.clone()
    header = bytes((seed & 0xFF, (seed >> 8) & 0xFF, len(encrypted_payload) & 0xFF, (len(encrypted_payload) >> 8) & 0xFF))
    encrypted_header = _xor_arc4(header, enc)
    changed = bias = 0
    for byte in encrypted_header:
        delta, delta_bias = _embed_value_byte(values, byte, iterator, bits_count, write=write, setter=setter)
        changed += delta
        bias += delta_bias
    iterator.seed(seed)
    remaining = len(encrypted_payload)
    for byte in encrypted_payload:
        iterator.adapt(bits_count, remaining)
        delta, delta_bias = _embed_value_byte(values, byte, iterator, bits_count, write=write, setter=setter)
        changed += delta
        bias += delta_bias
        remaining -= 1
    return changed, bias


def _embed_value_byte(values: list[int], value: int, iterator: _Iterator, bits_count: int, *, write: bool, setter) -> tuple[int, int]:
    changed = bias = 0
    for _ in range(8):
        index = iterator.off
        if index >= bits_count:
            raise ValueError("OutGuess 容量不足，迭代器越界")
        bit = value & 1
        old = values[index] & 1
        if old != bit:
            changed += 1
            bias += _jpeg_detect_weight(values[index]) if setter is _jpeg_sequence_setter else _pnm_detect_weight(values[index])
            if write:
                values[index] = setter(values[index], bit)
        value >>= 1
        iterator.next()
    return changed, bias


def _jpeg_sequence_setter(value: int, bit: int) -> int:
    return (value & ~1) | bit


def _jpeg_detect_weight(value: int) -> int:
    temp = abs(value)
    if temp >= 0x25:
        return -1
    if temp >= 0x04:
        return 0
    if temp >= 0x03:
        return 1
    return 2


def _iter_outguess_jpeg_coefficients(image) -> list[int]:
    return [_jpeg_get_position(image, position) for position in _iter_outguess_jpeg_positions(image)]


def _iter_outguess_jpeg_positions(image):
    mcus_x = (image.width + 8 * image.max_h - 1) // (8 * image.max_h)
    mcus_y = (image.height + 8 * image.max_v - 1) // (8 * image.max_v)
    component_index = {component["id"]: index for index, component in enumerate(image.components)}
    for mcu_y in range(mcus_y):
        for mcu_x in range(mcus_x):
            for scan_component in image.scan_components:
                index = component_index[scan_component["id"]]
                for block_y in range(scan_component["v"]):
                    for block_x in range(scan_component["h"]):
                        out_y = mcu_y * scan_component["v"] + block_y
                        out_x = mcu_x * scan_component["h"] + block_x
                        if out_y >= len(image.coefficients[index]):
                            continue
                        row = image.coefficients[index][out_y]
                        start = out_x * 64
                        if start + 64 > len(row):
                            continue
                        for coeff_index in range(64):
                            value = row[start + coeff_index]
                            if value not in {0, 1}:
                                yield (index, out_y, start + coeff_index)


def _jpeg_get_position(image, position: tuple[int, int, int]) -> int:
    component, row, offset = position
    return image.coefficients[component][row][offset]


def _jpeg_set_position(image, position: tuple[int, int, int], value: int) -> None:
    component, row, offset = position
    image.coefficients[component][row][offset] = value


def _read_jpeg_dct_image_for_outguess(input_path: Path):
    from oh_my_misc.jphs import _read_jpeg_dct_image

    return _read_jpeg_dct_image(input_path)


def _write_jpeg_dct_image_for_outguess(image, output_path: Path) -> None:
    from oh_my_misc.jphs import _write_jpeg_dct_image

    _write_jpeg_dct_image(image, output_path)


def extract_outguess_pnm(input_path: Path, *, key: str = "") -> bytes:
    """Native OutGuess extractor for PNM/PPM/PGM carriers."""

    image = _read_pnm(input_path)
    bits = [byte & 1 for byte in image["pixels"]]
    return _extract_outguess_from_bits(bits, key=key)


def hide_outguess_pnm(input_path: Path, payload: bytes, *, key: str = "") -> bytes:
    """Native OutGuess embedder for PNM/PPM/PGM carriers."""

    image = _read_pnm(input_path)
    pixels = bytearray(image["pixels"])
    if len(payload) > 0xFFFF:
        raise ValueError("OutGuess PNM 载荷不能超过 65535 bytes")
    if len(pixels) // (len(payload) * 8 if payload else 1) < 2:
        raise ValueError(f"OutGuess PNM 容量不足：payload={len(payload)} bytes, bits={len(pixels)}")
    enc = _Arc4("Encryption", key)
    body_enc = enc.clone()
    encrypted_payload = _xor_arc4(payload, body_enc)
    base_iterator = _Iterator(key)
    best_seed: int | None = None
    best_score: int | None = None
    last_error = ""
    for seed in range(256):
        trial_pixels = pixels.copy()
        try:
            changed, bias = _embed_outguess_sequence(trial_pixels, encrypted_payload, key=key, seed=seed, base_iterator=base_iterator, base_enc=enc, write=False, setter=_pnm_sequence_setter)
        except ValueError as error:
            last_error = str(error)
            continue
        score = changed + bias
        if best_score is None or score < best_score:
            best_seed = seed
            best_score = score
    if best_seed is None:
        raise ValueError(f"OutGuess PNM 找不到可用 seed：{last_error}")
    _embed_outguess_sequence(pixels, encrypted_payload, key=key, seed=best_seed, base_iterator=base_iterator, base_enc=enc, write=True, setter=_pnm_sequence_setter)
    return _write_pnm_bytes(image["magic"], image["width"], image["height"], image["maxval"], bytes(pixels))



def _pnm_sequence_setter(value: int, bit: int) -> int:
    return (value & 0xFE) | bit

def _retrieve_byte(bits: list[int], iterator: _Iterator) -> int:
    value = 0
    for where in range(8):
        index = iterator.off
        if index >= len(bits):
            raise ValueError("OutGuess PNM 数据不完整，迭代器越界")
        value |= bits[index] << where
        iterator.next()
    return value


def _xor_arc4(data: bytes, stream: _Arc4) -> bytes:
    return bytes(byte ^ stream.getbyte() for byte in data)


def _pnm_detect_weight(value: int) -> int:
    if value >= 0xF0:
        return -1
    if value <= 0x10:
        return 1
    return 0


def _is_native_supported(path: Path) -> bool:
    return _is_pnm(path) or _is_jpeg(path)


def _is_jpeg(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(2) == b"\xff\xd8"
    except OSError:
        return False


def _is_pnm(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            magic = stream.read(2)
        return magic in {b"P2", b"P3", b"P5", b"P6"}
    except OSError:
        return False


def _read_pnm(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    pos = 0

    def token() -> bytes:
        nonlocal pos
        while pos < len(data):
            byte = data[pos]
            if byte in b" \t\r\n":
                pos += 1
                continue
            if byte == ord("#"):
                while pos < len(data) and data[pos] not in b"\r\n":
                    pos += 1
                continue
            break
        start = pos
        while pos < len(data) and data[pos] not in b" \t\r\n#":
            pos += 1
        if start == pos:
            raise ValueError("PNM 头部不完整")
        return data[start:pos]

    magic = token().decode("ascii")
    if magic not in {"P2", "P3", "P5", "P6"}:
        raise ValueError(f"不支持的 PNM 类型：{magic}")
    width = int(token())
    height = int(token())
    maxval = int(token())
    if maxval <= 0 or maxval > 255 or width <= 1 or height <= 1:
        raise ValueError("PNM 参数超出 OutGuess 支持范围")
    depth = 1 if magic in {"P2", "P5"} else 3
    count = width * height * depth
    if magic in {"P2", "P3"}:
        pixels = bytearray()
        for _ in range(count):
            pixels.append(int(token()))
    else:
        if pos < len(data) and data[pos] in b" \t\r\n":
            pos += 1
        pixels = bytearray(data[pos : pos + count])
        if len(pixels) != count:
            raise ValueError("PNM 像素数据长度不足")
    if any(pixel > maxval for pixel in pixels):
        raise ValueError("PNM 像素值超过 maxval")
    return {"magic": magic, "width": width, "height": height, "maxval": maxval, "pixels": bytes(pixels)}


def _write_pnm_bytes(magic: str, width: int, height: int, maxval: int, pixels: bytes) -> bytes:
    output_magic = "P5" if magic in {"P2", "P5"} else "P6"
    header = f"{output_magic}\n{width} {height}\n{maxval}\n".encode("ascii")
    return header + pixels


def _key_candidates(wordlist_path: Path, *, include_empty: bool) -> list[str]:
    candidates: list[str] = []
    if include_empty:
        candidates.append("")
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            candidate = line.rstrip("\r\n")
            if candidate or candidate not in candidates:
                candidates.append(candidate)
    return candidates


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
