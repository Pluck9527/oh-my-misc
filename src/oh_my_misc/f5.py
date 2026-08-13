from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path

from oh_my_misc.jphs import _JpegDctImage, _read_jpeg_dct_image, _write_jpeg_dct_image

MAX_F5_PAYLOAD = 0x007FFFFF


@dataclass(frozen=True)
class F5Result:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    password_used: bool
    found_password: str | None = None
    attempts: int = 0
    written_bytes: int = 0
    stdout: str = ""
    stderr: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def extract_f5(
    input_path: Path,
    output_path: Path,
    *,
    password: str = "abc123",
) -> F5Result:
    """Extract F5 steganography payload from a baseline JPEG using the native Python port."""

    _check_file(input_path, "JPEG 文件")
    image = _read_jpeg_dct_image(input_path)
    payload = extract_f5_payload_from_image(image, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return F5Result(
        operation="image.f5.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        password_used=bool(password),
        found_password=password if password else None,
        attempts=1,
        written_bytes=len(payload),
    )


def hide_f5(
    input_path: Path,
    output_path: Path,
    payload_path: Path,
    *,
    password: str = "abc123",
) -> F5Result:
    """Embed F5 payload into an existing baseline JPEG DCT stream."""

    _check_file(input_path, "JPEG 文件")
    _check_file(payload_path, "载荷文件")
    image = _read_jpeg_dct_image(input_path)
    payload = payload_path.read_bytes()
    embed_f5_payload_in_image(image, payload, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_jpeg_dct_image(image, output_path)
    return F5Result(
        operation="image.f5.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        password_used=bool(password),
        found_password=password if password else None,
        attempts=1,
        written_bytes=output_path.stat().st_size if output_path.exists() else 0,
    )


def brute_f5(
    input_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    contains: bytes | None = None,
    prefix: bytes | None = None,
    include_default: bool = True,
) -> F5Result:
    """Try F5 passwords from a text dictionary and keep the first matching payload."""

    _check_file(input_path, "JPEG 文件")
    _check_file(wordlist_path, "字典")
    image = _read_jpeg_dct_image(input_path)
    attempts = 0
    last_error = ""
    for candidate in _password_candidates(wordlist_path, include_default=include_default):
        attempts += 1
        try:
            payload = extract_f5_payload_from_image(image, password=candidate)
        except ValueError as error:
            last_error = str(error)
            continue
        if contains is not None and contains not in payload:
            continue
        if prefix is not None and not payload.startswith(prefix):
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        return F5Result(
            operation="image.f5.brute",
            input_path=str(input_path),
            output_path=str(output_path),
            output_paths=[str(output_path)],
            password_used=bool(candidate),
            found_password=candidate,
            attempts=attempts,
            written_bytes=len(payload),
        )
    extra = f"；最后错误：{last_error}" if last_error else ""
    raise ValueError(f"F5 字典爆破失败，尝试 {attempts} 个密码{extra}")


def extract_f5_payload_from_image(image: _JpegDctImage, *, password: str = "abc123") -> bytes:
    coefficients = _flatten_f5_coefficients(image)
    random = _F5Random(password.encode())
    permutation = _Permutation(len(coefficients), random)
    extracted_length = 0
    available_bits = 0
    index = 0
    while available_bits < 32 and index < len(coefficients):
        shuffled_index = permutation.get(index)
        index += 1
        if shuffled_index % 64 == 0:
            continue
        coeff = coefficients[shuffled_index]
        if coeff == 0:
            continue
        extracted_length |= _f5_coeff_bit(coeff) << available_bits
        available_bits += 1
    if available_bits < 32:
        raise ValueError("F5 长度字段不完整")
    extracted_length ^= random.get_next_byte()
    extracted_length ^= random.get_next_byte() << 8
    extracted_length ^= random.get_next_byte() << 16
    extracted_length ^= random.get_next_byte() << 24
    k = _java_remainder(_java_shift_right(extracted_length, 24), 32)
    if k < 0 or k > 7:
        raise ValueError(f"F5 matrix code 参数异常：k={k}")
    n = (1 << k) - 1
    length = extracted_length & MAX_F5_PAYLOAD
    _validate_length(length, coefficients)
    payload = bytearray()
    extracted_byte = 0
    available_extracted_bits = 0
    if n > 0:
        start_of_n = index
        while len(payload) < length:
            hash_value = 0
            code = 1
            scan_offset = 0
            while code <= n:
                if start_of_n + scan_offset >= len(coefficients):
                    raise ValueError("F5 数据不完整")
                shuffled_index = permutation.get(start_of_n + scan_offset)
                scan_offset += 1
                if shuffled_index % 64 == 0:
                    continue
                coeff = coefficients[shuffled_index]
                if coeff == 0:
                    continue
                if _f5_coeff_bit(coeff) == 1:
                    hash_value ^= code
                code += 1
            start_of_n += scan_offset
            for bit_index in range(k):
                extracted_byte |= ((hash_value >> bit_index) & 1) << available_extracted_bits
                available_extracted_bits += 1
                if available_extracted_bits == 8:
                    payload.append((extracted_byte ^ random.get_next_byte()) & 0xFF)
                    extracted_byte = 0
                    available_extracted_bits = 0
                    if len(payload) == length:
                        return bytes(payload)
    else:
        while index < len(coefficients) and len(payload) < length:
            shuffled_index = permutation.get(index)
            index += 1
            if shuffled_index % 64 == 0:
                continue
            coeff = coefficients[shuffled_index]
            if coeff == 0:
                continue
            extracted_byte |= _f5_coeff_bit(coeff) << available_extracted_bits
            available_extracted_bits += 1
            if available_extracted_bits == 8:
                payload.append((extracted_byte ^ random.get_next_byte()) & 0xFF)
                extracted_byte = 0
                available_extracted_bits = 0
    if len(payload) < length:
        raise ValueError(f"F5 数据不完整：只恢复 {len(payload)} / {length} 字节")
    return bytes(payload)


def embed_f5_payload_in_image(image: _JpegDctImage, payload: bytes, *, password: str = "abc123") -> None:
    if len(payload) > MAX_F5_PAYLOAD:
        raise ValueError("F5 载荷最大支持 8388607 字节")
    positions = _flatten_f5_positions(image)
    coefficients = [row[col] for row, col in positions]
    expected, one_count, large_count, zero_count = _expected_capacity(coefficients)
    random = _F5Random(password.encode())
    permutation = _Permutation(len(coefficients), random)
    k = _choose_f5_k(expected, len(payload))
    n = (1 << k) - 1
    if n == 0:
        n = 1
    status_word = len(payload) | (k << 24)
    status_word ^= random.get_next_byte()
    status_word ^= random.get_next_byte() << 8
    status_word ^= random.get_next_byte() << 16
    status_word ^= random.get_next_byte() << 24
    bit_to_embed = status_word & 1
    status_word = _java_shift_right(status_word, 1)
    available_bits = 31
    index = 0
    if n > 1:
        while index < len(coefficients):
            shuffled_index = permutation.get(index)
            index += 1
            if shuffled_index % 64 == 0 or coefficients[shuffled_index] == 0:
                continue
            _set_f5_coeff_bit(positions, coefficients, shuffled_index, bit_to_embed)
            if coefficients[shuffled_index] != 0:
                if available_bits == 0:
                    break
                bit_to_embed = status_word & 1
                status_word = _java_shift_right(status_word, 1)
                available_bits -= 1
        start_of_n = index
        payload_index = 0
        is_last_byte = False
        byte_to_embed = 0
        data_bits_available = 0
        while not is_last_byte:
            bits_to_embed = 0
            for bit_index in range(k):
                if data_bits_available == 0:
                    if payload_index == len(payload):
                        is_last_byte = True
                        break
                    byte_to_embed = payload[payload_index] ^ random.get_next_byte()
                    payload_index += 1
                    data_bits_available = 8
                bit_to_embed = byte_to_embed & 1
                byte_to_embed >>= 1
                data_bits_available -= 1
                bits_to_embed |= bit_to_embed << bit_index
            while True:
                code_word: list[int] = []
                scan = start_of_n
                while len(code_word) < n:
                    if scan >= len(coefficients):
                        raise ValueError(
                            f"F5 容量不足：expected={expected}, one={one_count}, large={large_count}, zero={zero_count}"
                        )
                    shuffled_index = permutation.get(scan)
                    scan += 1
                    if shuffled_index % 64 == 0 or coefficients[shuffled_index] == 0:
                        continue
                    code_word.append(shuffled_index)
                end_of_n = scan
                hash_value = 0
                for word_index, coeff_index in enumerate(code_word, start=1):
                    if _f5_coeff_bit(coefficients[coeff_index]) == 1:
                        hash_value ^= word_index
                change_index = hash_value ^ bits_to_embed
                if change_index == 0:
                    break
                coeff_index = code_word[change_index - 1]
                _decrease_abs(positions, coefficients, coeff_index)
                if coefficients[coeff_index] != 0:
                    break
            start_of_n = end_of_n
    else:
        payload_index = 0
        while index < len(coefficients):
            shuffled_index = permutation.get(index)
            index += 1
            if shuffled_index % 64 == 0 or coefficients[shuffled_index] == 0:
                continue
            _set_f5_coeff_bit(positions, coefficients, shuffled_index, bit_to_embed)
            if coefficients[shuffled_index] != 0:
                if available_bits == 0:
                    if payload_index == len(payload):
                        break
                    status_word = payload[payload_index] ^ random.get_next_byte()
                    payload_index += 1
                    available_bits = 8
                bit_to_embed = status_word & 1
                status_word >>= 1
                available_bits -= 1
        if payload_index < len(payload):
            raise ValueError(f"F5 容量不足：expected={expected}, one={one_count}, large={large_count}, zero={zero_count}")


def _flatten_f5_coefficients(image: _JpegDctImage) -> list[int]:
    return [row[col] for row, col in _flatten_f5_positions(image)]


def _flatten_f5_positions(image: _JpegDctImage) -> list[tuple[list[int], int]]:
    positions: list[tuple[list[int], int]] = []
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
                        for offset in range(64):
                            positions.append((row, start + offset))
    return positions


def _f5_coeff_bit(coeff: int) -> int:
    if coeff > 0:
        return coeff & 1
    return 1 - (coeff & 1)


def _set_f5_coeff_bit(
    positions: list[tuple[list[int], int]], coefficients: list[int], index: int, bit: int
) -> None:
    coeff = coefficients[index]
    if coeff > 0:
        if (coeff & 1) != bit:
            _decrease_abs(positions, coefficients, index)
    else:
        if (coeff & 1) == bit:
            _decrease_abs(positions, coefficients, index)


def _decrease_abs(positions: list[tuple[list[int], int]], coefficients: list[int], index: int) -> None:
    coeff = coefficients[index]
    if coeff > 0:
        coeff -= 1
    else:
        coeff += 1
    coefficients[index] = coeff
    row, col = positions[index]
    row[col] = coeff


def _expected_capacity(coefficients: list[int]) -> tuple[int, int, int, int]:
    one_count = 0
    zero_count = 0
    for index, coeff in enumerate(coefficients):
        if index % 64 == 0:
            continue
        if coeff in {1, -1}:
            one_count += 1
        if coeff == 0:
            zero_count += 1
    large_count = len(coefficients) - zero_count - one_count - len(coefficients) // 64
    expected = large_count + int(0.49 * one_count)
    return expected, one_count, large_count, zero_count


def _choose_f5_k(expected: int, payload_len: int) -> int:
    chosen = 0
    for i in range(1, 8):
        n = (1 << i) - 1
        usable = expected * i // n
        usable = usable - usable % n
        usable //= 8
        if usable == 0:
            break
        if usable < payload_len + 4:
            break
        chosen = i
    return chosen


def _validate_length(length: int, coefficients: list[int]) -> None:
    if length < 0:
        raise ValueError(f"F5 载荷长度异常：{length}")
    max_reasonable = max(0, len(coefficients) // 8)
    if length > max(MAX_F5_PAYLOAD, max_reasonable):
        raise ValueError(f"F5 载荷长度异常：{length}")
    if length > max_reasonable:
        raise ValueError(f"F5 载荷长度超过当前 JPEG 理论容量：{length} > {max_reasonable}")


class _F5Random:
    def __init__(self, password: bytes):
        self._rng = _Sha1Prng(password)

    def get_next_byte(self) -> int:
        return _signed_byte(self._rng.next_bytes(1)[0])

    def get_next_value(self, max_value: int) -> int:
        value = (
            self.get_next_byte()
            | (self.get_next_byte() << 8)
            | (self.get_next_byte() << 16)
            | (self.get_next_byte() << 24)
        )
        return _java_remainder(value, max_value) % max_value


class _Permutation:
    def __init__(self, size: int, random: _F5Random):
        self.shuffled = list(range(size))
        max_random = size
        for _ in range(size):
            random_index = random.get_next_value(max_random)
            max_random -= 1
            self.shuffled[random_index], self.shuffled[max_random] = (
                self.shuffled[max_random],
                self.shuffled[random_index],
            )

    def get(self, index: int) -> int:
        return self.shuffled[index]


class _Sha1Prng:
    def __init__(self, seed: bytes):
        self.state = hashlib.sha1(seed).digest()
        self.remainder = b""
        self.remainder_index = 0

    def next_bytes(self, count: int) -> bytes:
        out = bytearray()
        if self.remainder_index < len(self.remainder):
            take = min(count, len(self.remainder) - self.remainder_index)
            out.extend(self.remainder[self.remainder_index : self.remainder_index + take])
            self.remainder_index += take
        while len(out) < count:
            digest = hashlib.sha1(self.state).digest()
            self.state = self._update_state(self.state, digest)
            take = min(count - len(out), len(digest))
            out.extend(digest[:take])
            self.remainder = digest
            self.remainder_index = take
        return bytes(out)

    @staticmethod
    def _update_state(state: bytes, output: bytes) -> bytes:
        new_state = bytearray(state)
        carry = 1
        changed = False
        for index, value in enumerate(new_state):
            total = _signed_byte(value) + _signed_byte(output[index]) + carry
            replacement = total & 0xFF
            changed |= value != replacement
            new_state[index] = replacement
            carry = total >> 8
        if not changed:
            new_state[0] = (new_state[0] + 1) & 0xFF
        return bytes(new_state)


def _java_remainder(value: int, divisor: int) -> int:
    return value - int(value / divisor) * divisor


def _java_shift_right(value: int, bits: int) -> int:
    value = _int32(value)
    return value >> bits


def _int32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def _signed_byte(value: int) -> int:
    return value - 256 if value >= 128 else value


def _password_candidates(wordlist_path: Path, *, include_default: bool) -> list[str]:
    candidates: list[str] = []
    if include_default:
        candidates.append("abc123")
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            candidate = line.rstrip("\r\n")
            if candidate or candidate not in candidates:
                candidates.append(candidate)
    return candidates


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
