from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path

from Crypto.Cipher import Blowfish

from oh_my_misc.jphs_ltable import LTAB, TAIL1, TAIL2, TAIL3

JPEG_ZIGZAG = (
    0,
    1,
    8,
    16,
    9,
    2,
    3,
    10,
    17,
    24,
    32,
    25,
    18,
    11,
    4,
    5,
    12,
    19,
    26,
    33,
    40,
    48,
    41,
    34,
    27,
    20,
    13,
    6,
    7,
    14,
    21,
    28,
    35,
    42,
    49,
    56,
    57,
    50,
    43,
    36,
    29,
    22,
    15,
    23,
    30,
    37,
    44,
    51,
    58,
    59,
    52,
    45,
    38,
    31,
    39,
    46,
    53,
    60,
    61,
    54,
    47,
    55,
    62,
    63,
)


@dataclass(frozen=True)
class JphsResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    tool_path: str
    runner_path: str | None
    password_used: bool
    found_password: str | None = None
    attempts: int = 0
    written_bytes: int = 0
    stdout: str = ""
    stderr: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def hide_jphs(
    input_path: Path,
    output_path: Path,
    payload_path: Path,
    *,
    password: str = "",
    jphide_path: Path | None = None,
    wine_path: Path | None = None,
    backend: str = "python",
) -> JphsResult:
    """Embed JPHS data with the native Python backend."""

    _check_file(input_path, "JPEG 文件")
    _check_file(payload_path, "载荷文件")
    if backend not in {"tool", "python", "auto"}:
        raise ValueError("backend 必须是 tool、python 或 auto")
    _ = (jphide_path, wine_path)
    return hide_jphs_python(input_path, output_path, payload_path, password=password)


def hide_jphs_python(
    input_path: Path,
    output_path: Path,
    payload_path: Path,
    *,
    password: str,
) -> JphsResult:
    """Pure-Python JPHS/JPHide embedder for baseline sequential JPEG files."""

    _check_file(input_path, "JPEG 文件")
    _check_file(payload_path, "载荷文件")
    image = _read_jpeg_dct_image(input_path)
    payload = payload_path.read_bytes()
    embed_jphs_payload_in_coefficients(image.coefficients, payload, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_jpeg_dct_image(image, output_path)
    return JphsResult(
        operation="image.jphs.hide-python",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        runner_path=None,
        password_used=bool(password),
        found_password=password if password else None,
        attempts=1,
        written_bytes=output_path.stat().st_size if output_path.exists() else 0,
    )


def extract_jphs(
    input_path: Path,
    output_path: Path,
    *,
    password: str = "",
    jpseek_path: Path | None = None,
    wine_path: Path | None = None,
    backend: str = "python",
) -> JphsResult:
    """Extract JPHS data with the native Python backend."""

    _check_file(input_path, "JPEG 文件")
    if backend not in {"tool", "python", "auto"}:
        raise ValueError("backend 必须是 tool、python 或 auto")
    _ = (jpseek_path, wine_path)
    return extract_jphs_python(input_path, output_path, password=password)


def extract_jphs_python(
    input_path: Path,
    output_path: Path,
    *,
    password: str,
) -> JphsResult:
    """Pure-Python JPHS/JPSeek extractor for baseline sequential JPEG files."""

    _check_file(input_path, "JPEG 文件")
    coefficients = _read_jpeg_dct_coefficients(input_path)
    payload = extract_jphs_payload_from_coefficients(coefficients, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return JphsResult(
        operation="image.jphs.extract-python",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        runner_path=None,
        password_used=bool(password),
        found_password=password if password else None,
        attempts=1,
        written_bytes=len(payload),
    )


def extract_jphs_payload_from_coefficients(
    coefficients: list[list[list[int]]],
    *,
    password: str,
) -> bytes:
    if len(coefficients) != 3:
        raise ValueError(f"JPHS 需要 3 个 JPEG 分量，当前为 {len(coefficients)}")
    state = _JphsState(coefficients, password)
    length_block = bytearray()
    for _ in range(8):
        value = 0
        for bit_index in range(8):
            bit = state.get_bit()
            value |= bit << bit_index
        length_block.append(value)
    decrypted_length = state.cipher.decrypt(bytes(length_block))
    length = (decrypted_length[0] << 16) | (decrypted_length[1] << 8) | decrypted_length[2]
    if length < 0 or length > 64 * 1024 * 1024:
        raise ValueError(f"JPHS 载荷长度异常：{length}")
    state.tail = length * 8 - TAIL1
    state.tail_on = 0
    payload = bytearray()
    for _ in range(length):
        value = 0
        for _ in range(8):
            bit = state.get_bit()
            bit ^= state.get_code_bit(1)
            value = (value << 1) | bit
            state.tail -= 1
        payload.append(value)
    return bytes(payload)


def embed_jphs_payload_in_coefficients(
    coefficients: list[list[list[int]]],
    payload: bytes,
    *,
    password: str,
) -> None:
    if len(payload) > 0xFFFFFF:
        raise ValueError("JPHS 载荷最大支持 16777215 字节")
    if len(coefficients) != 3:
        raise ValueError(f"JPHS 需要 3 个 JPEG 分量，当前为 {len(coefficients)}")
    state = _JphsState(coefficients, password)
    length_block = bytearray(state.cipher.encrypt(state.length_iv))
    length_block[0] = (len(payload) >> 16) & 0xFF
    length_block[1] = (len(payload) >> 8) & 0xFF
    length_block[2] = len(payload) & 0xFF
    encrypted_length = state.cipher.encrypt(bytes(length_block))
    state.tail = len(payload) * 8 - TAIL1
    state.tail_on = 0
    for byte in encrypted_length:
        for bit_index in range(8):
            state.put_bit((byte >> bit_index) & 1)
    for byte in payload:
        for bit_index in range(8):
            data_bit = (byte >> (7 - bit_index)) & 1
            state.put_bit(data_bit ^ state.get_code_bit(1))
            state.tail -= 1




def brute_jphs(
    input_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    jpseek_path: Path | None = None,
    wine_path: Path | None = None,
    backend: str = "python",
    contains: bytes | None = None,
    prefix: bytes | None = None,
    include_empty: bool = True,
) -> JphsResult:
    """Try JPHS passphrases from a text dictionary and keep the first matching payload."""

    _check_file(input_path, "JPEG 文件")
    _check_file(wordlist_path, "字典")
    if backend not in {"tool", "python", "auto"}:
        raise ValueError("backend 必须是 tool、python 或 auto")
    _ = (jpseek_path, wine_path)
    return _brute_jphs_python(
        input_path,
        wordlist_path,
        output_path,
        contains=contains,
        prefix=prefix,
        include_empty=include_empty,
    )


def _brute_jphs_python(
    input_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    contains: bytes | None,
    prefix: bytes | None,
    include_empty: bool,
) -> JphsResult:
    coefficients = _read_jpeg_dct_coefficients(input_path)
    attempts = 0
    last_error = ""
    for candidate in _password_candidates(wordlist_path, include_empty=include_empty):
        attempts += 1
        try:
            payload = extract_jphs_payload_from_coefficients(coefficients, password=candidate)
        except ValueError as error:
            last_error = str(error)
            continue
        if contains is not None and contains not in payload:
            continue
        if prefix is not None and not payload.startswith(prefix):
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        return JphsResult(
            operation="image.jphs.brute-python",
            input_path=str(input_path),
            output_path=str(output_path),
            output_paths=[str(output_path)],
            tool_path="python",
            runner_path=None,
            password_used=bool(candidate),
            found_password=candidate,
            attempts=attempts,
            written_bytes=len(payload),
        )
    extra = f"；最后错误：{last_error}" if last_error else ""
    raise ValueError(f"JPHS Python 字典爆破失败，尝试 {attempts} 个密码{extra}")


class _JphsState:
    def __init__(self, coefficients: list[list[list[int]]], password: str):
        key = password.encode("utf-8") or b"\x00\x00\x00\x00"
        try:
            self.cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        except ValueError as error:
            raise ValueError("纯 Python JPHS 后端需要 4..56 字节 Blowfish passphrase") from error
        self.coefficients = coefficients
        self.hib = [len(component) for component in coefficients]
        self.wib = [len(component[0]) - 1 if component else -1 for component in coefficients]
        iv = bytearray((coefficients[0][0][index] & 0xFF) for index in range(8))
        self.cpos = [0, 0, 0, 0]
        self.cdata: list[bytearray] = []
        for _ in range(4):
            self.cdata.append(bytearray(self.cipher.encrypt(bytes(iv[:8]))))
            iv.append(iv[0])
            del iv[0]
        self.length_iv = bytes(iv[:8])
        self.coef = LTAB[0]
        self.spos = LTAB[1]
        self.mode = LTAB[2]
        self.d = 0
        self.lh = 0
        self.lw = self.spos - 64
        self.lt = 0
        self.tail = 0
        self.tail_on = 0

    def get_code_bit(self, stream_index: int) -> int:
        bit_position = self.cpos[stream_index] & 63
        if bit_position == 0:
            self.cdata[stream_index] = bytearray(
                self.cipher.encrypt(bytes(self.cdata[stream_index]))
            )
        byte_index = bit_position >> 3
        offset = bit_position & 7
        value = (self.cdata[stream_index][byte_index] << offset) & 0xFF
        self.cpos[stream_index] += 1
        return value >> 7

    def get_word(self) -> int:
        while True:
            self.lw += 64
            if self.lw > self.wib[self.coef]:
                self.lw = self.spos
                self.lh += 1
                if not self.lh < self.hib[self.coef]:
                    self.lt += 3
                    if LTAB[self.lt] < 0:
                        raise ValueError("File not completely recovered")
                    if self.tail < 0:
                        if self.tail_on == 2:
                            self.tail_on = 3
                            self.tail = 999999
                        if self.tail_on == 1:
                            self.tail_on = 2
                            self.tail = TAIL3
                        if self.tail_on == 0:
                            self.tail_on = 1
                            self.tail = TAIL2
                    self.coef = LTAB[self.lt]
                    self.lw = self.spos = LTAB[self.lt + 1]
                    self.lh = 0
                    self.mode = LTAB[self.lt + 2]
            y = self.coefficients[self.coef][self.lh][self.lw]
            ok = 1 if (self.coef or self.lh or self.lw > 7) else 0
            if ok:
                if self.mode < 0:
                    if (y > -self.mode) or (y < self.mode):
                        ok = self.get_code_bit(0)
                        ok = (ok << 1) | self.get_code_bit(0)
                    else:
                        ok = 0
                else:
                    if self.mode == 3:
                        ok = self.get_code_bit(0)
                    else:
                        ok = 1
                    if ok:
                        if (y > 1) or (y < -1):
                            ok = 0
                        else:
                            ok = self.get_code_bit(0)
                            if self.mode:
                                ok = (ok << 1) | self.get_code_bit(0)
                        if ok:
                            ok = 0
                        else:
                            if self.mode > 1:
                                ok = self.get_code_bit(0)
                            else:
                                ok = 1
            if ok and self.tail_on > 0:
                ok = self.get_code_bit(2)
            if ok and self.tail_on > 1:
                ok = self.get_code_bit(2)
            if ok and self.tail_on > 2:
                ok = self.get_code_bit(2)
            if ok:
                return y

    def get_bit(self) -> int:
        return _demerge_word(self.get_word(), self.mode)

    def put_bit(self, bit: int) -> None:
        word = self.get_word()
        self.coefficients[self.coef][self.lh][self.lw] = self.merge_word(word, bit)

    def merge_word(self, word: int, bit: int) -> int:
        if self.mode < 0:
            value = bit << 1
            if word > 0:
                return (word & ~2) | value
            return -(((-word) & ~2) | value)
        if word == 0:
            self.d = -self.d
            return self.d * bit
        if word in {-1, 1}:
            self.d = word
            return bit * word
        if word > 0:
            self.d = 1
            return (word & ~1) | bit
        self.d = -1
        return -(((-word) & ~1) | bit)


def _demerge_word(word: int, mode: int) -> int:
    value = -word if word < 0 else word
    if mode < 0:
        return (value & 2) >> 1
    return value & 1


def _password_candidates(wordlist_path: Path, *, include_empty: bool) -> list[str]:
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


@dataclass
class _JpegDctImage:
    coefficients: list[list[list[int]]]
    components: list[dict[str, int]]
    scan_components: list[dict[str, int]]
    width: int
    height: int
    max_h: int
    max_v: int
    restart_interval: int
    huffman_decode: dict[tuple[int, int], dict[tuple[int, int], int]]
    huffman_encode: dict[tuple[int, int], dict[int, tuple[int, int]]]
    prefix: bytes
    suffix: bytes


def _read_jpeg_dct_coefficients(path: Path) -> list[list[list[int]]]:
    return _read_jpeg_dct_image(path).coefficients


def _read_jpeg_dct_image(path: Path) -> _JpegDctImage:
    data = path.read_bytes()
    parser = _JpegDctParser(data)
    return parser.parse_image()


def _write_jpeg_dct_image(image: _JpegDctImage, path: Path) -> None:
    if image.restart_interval:
        raise ValueError("纯 Python JPHS 写入暂不支持带 DRI restart interval 的 JPEG")
    path.write_bytes(image.prefix + _encode_jpeg_entropy(image) + image.suffix)


class _JpegDctParser:
    def __init__(self, data: bytes):
        if not data.startswith(b"\xff\xd8"):
            raise ValueError("不是 JPEG 文件")
        self.data = data
        self.pos = 2
        self.huffman: dict[tuple[int, int], dict[tuple[int, int], int]] = {}
        self.huffman_encode: dict[tuple[int, int], dict[int, tuple[int, int]]] = {}
        self.prefix = b""
        self.suffix = b""
        self.components: list[dict[str, int]] = []
        self.scan_components: list[dict[str, int]] = []
        self.width = 0
        self.height = 0
        self.max_h = 1
        self.max_v = 1
        self.restart_interval = 0

    def parse_image(self) -> _JpegDctImage:
        while self.pos < len(self.data):
            marker = self._next_marker()
            if marker == 0xD9:
                break
            if marker == 0xC0:
                self._parse_sof0()
            elif marker == 0xC4:
                self._parse_dht()
            elif marker == 0xDD:
                self._parse_dri()
            elif marker == 0xDA:
                coefficients = self._parse_sos_and_decode()
                return _JpegDctImage(
                    coefficients=coefficients,
                    components=deepcopy(self.components),
                    scan_components=deepcopy(self.scan_components),
                    width=self.width,
                    height=self.height,
                    max_h=self.max_h,
                    max_v=self.max_v,
                    restart_interval=self.restart_interval,
                    huffman_decode=deepcopy(self.huffman),
                    huffman_encode=deepcopy(self.huffman_encode),
                    prefix=self.prefix,
                    suffix=self.suffix,
                )
            else:
                self._skip_segment()
        raise ValueError("JPEG 缺少 baseline scan 数据")

    def _next_marker(self) -> int:
        data = self.data
        while self.pos < len(data) and data[self.pos] != 0xFF:
            self.pos += 1
        while self.pos < len(data) and data[self.pos] == 0xFF:
            self.pos += 1
        if self.pos >= len(data):
            raise ValueError("JPEG marker 不完整")
        marker = data[self.pos]
        self.pos += 1
        return marker

    def _segment(self) -> bytes:
        if self.pos + 2 > len(self.data):
            raise ValueError("JPEG segment 长度不完整")
        length = int.from_bytes(self.data[self.pos : self.pos + 2], "big")
        if length < 2 or self.pos + length > len(self.data):
            raise ValueError("JPEG segment 长度越界")
        body = self.data[self.pos + 2 : self.pos + length]
        self.pos += length
        return body

    def _skip_segment(self) -> None:
        self._segment()

    def _parse_sof0(self) -> None:
        body = self._segment()
        if len(body) < 6 or body[0] != 8:
            raise ValueError("仅支持 8-bit baseline JPEG")
        self.height = int.from_bytes(body[1:3], "big")
        self.width = int.from_bytes(body[3:5], "big")
        count = body[5]
        if count != 3:
            raise ValueError(f"JPHS 需要 3 分量 JPEG，当前为 {count}")
        self.components = []
        offset = 6
        for _ in range(count):
            component_id = body[offset]
            sampling = body[offset + 1]
            self.components.append(
                {
                    "id": component_id,
                    "h": sampling >> 4,
                    "v": sampling & 15,
                    "tq": body[offset + 2],
                    "dc": 0,
                    "ac": 0,
                }
            )
            offset += 3
        self.max_h = max(component["h"] for component in self.components)
        self.max_v = max(component["v"] for component in self.components)

    def _parse_dht(self) -> None:
        body = self._segment()
        offset = 0
        while offset < len(body):
            table_info = body[offset]
            offset += 1
            table_class = table_info >> 4
            table_id = table_info & 15
            counts = body[offset : offset + 16]
            offset += 16
            code = 0
            table: dict[tuple[int, int], int] = {}
            encode_table: dict[int, tuple[int, int]] = {}
            for bit_length, count in enumerate(counts, start=1):
                for _ in range(count):
                    symbol = body[offset]
                    table[(bit_length, code)] = symbol
                    encode_table[symbol] = (bit_length, code)
                    offset += 1
                    code += 1
                code <<= 1
            self.huffman[(table_class, table_id)] = table
            self.huffman_encode[(table_class, table_id)] = encode_table

    def _parse_dri(self) -> None:
        body = self._segment()
        if len(body) >= 2:
            self.restart_interval = int.from_bytes(body[:2], "big")

    def _parse_sos_and_decode(self) -> list[list[list[int]]]:
        body = self._segment()
        scan_count = body[0]
        components_by_id = {component["id"]: component for component in self.components}
        self.scan_components = []
        offset = 1
        for _ in range(scan_count):
            component = dict(components_by_id[body[offset]])
            tables = body[offset + 1]
            component["dc"] = tables >> 4
            component["ac"] = tables & 15
            self.scan_components.append(component)
            offset += 2
        if body[offset : offset + 3] != b"\x00\x3f\x00":
            raise ValueError("仅支持 baseline sequential JPEG scan")
        self.prefix = self.data[: self.pos]
        entropy = self._read_entropy_bytes()
        return self._decode_entropy(entropy)

    def _read_entropy_bytes(self) -> bytes:
        out = bytearray()
        data = self.data
        pos = self.pos
        while pos < len(data):
            byte = data[pos]
            pos += 1
            if byte != 0xFF:
                out.append(byte)
                continue
            if pos >= len(data):
                break
            marker = data[pos]
            pos += 1
            if marker == 0x00:
                out.append(0xFF)
                continue
            if 0xD0 <= marker <= 0xD7:
                continue
            self.pos = pos - 2
            self.suffix = data[self.pos :]
            return bytes(out)
        self.pos = pos
        self.suffix = b""
        return bytes(out)

    def _decode_entropy(self, entropy: bytes) -> list[list[list[int]]]:
        if not self.components:
            raise ValueError("JPEG 缺少 SOF0")
        reader = _EntropyBitReader(entropy)
        mcus_x = (self.width + 8 * self.max_h - 1) // (8 * self.max_h)
        mcus_y = (self.height + 8 * self.max_v - 1) // (8 * self.max_v)
        coefficients: list[list[list[int]]] = []
        for component in self.components:
            component_width = (self.width * component["h"] + self.max_h - 1) // self.max_h
            component_height = (self.height * component["v"] + self.max_v - 1) // self.max_v
            blocks_x = (component_width + 7) // 8
            blocks_y = (component_height + 7) // 8
            coefficients.append([[0] * (blocks_x * 64) for _ in range(blocks_y)])
        dc_previous = {component["id"]: 0 for component in self.components}
        component_index = {component["id"]: index for index, component in enumerate(self.components)}
        for mcu_y in range(mcus_y):
            for mcu_x in range(mcus_x):
                for scan_component in self.scan_components:
                    for block_y in range(scan_component["v"]):
                        for block_x in range(scan_component["h"]):
                            block, dc_value = self._decode_block(reader, scan_component, dc_previous)
                            dc_previous[scan_component["id"]] = dc_value
                            index = component_index[scan_component["id"]]
                            out_y = mcu_y * scan_component["v"] + block_y
                            out_x = mcu_x * scan_component["h"] + block_x
                            if out_y < len(coefficients[index]):
                                row = coefficients[index][out_y]
                                start = out_x * 64
                                if start + 64 <= len(row):
                                    row[start : start + 64] = block
        return coefficients

    def _decode_block(
        self,
        reader: _EntropyBitReader,
        component: dict[str, int],
        dc_previous: dict[int, int],
    ) -> tuple[list[int], int]:
        block = [0] * 64
        dc_table = self.huffman.get((0, component["dc"]))
        ac_table = self.huffman.get((1, component["ac"]))
        if dc_table is None or ac_table is None:
            raise ValueError("JPEG 缺少 Huffman 表")
        dc_size = reader.decode_symbol(dc_table)
        dc_diff = reader.receive_extend(dc_size)
        dc_value = dc_previous[component["id"]] + dc_diff
        block[0] = dc_value
        index = 1
        while index < 64:
            symbol = reader.decode_symbol(ac_table)
            run = symbol >> 4
            size = symbol & 15
            if size == 0:
                if run == 0:
                    break
                if run == 15:
                    index += 16
                    continue
                raise ValueError("JPEG AC Huffman 符号无效")
            index += run
            if index >= 64:
                raise ValueError("JPEG AC run 越界")
            block[JPEG_ZIGZAG[index]] = reader.receive_extend(size)
            index += 1
        return block, dc_value


class _EntropyBitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.bit_pos = 0

    def read_bit(self) -> int:
        byte_index = self.bit_pos >> 3
        if byte_index >= len(self.data):
            raise ValueError("JPEG entropy 数据不足")
        shift = 7 - (self.bit_pos & 7)
        self.bit_pos += 1
        return (self.data[byte_index] >> shift) & 1

    def read_bits(self, count: int) -> int:
        value = 0
        for _ in range(count):
            value = (value << 1) | self.read_bit()
        return value

    def receive_extend(self, size: int) -> int:
        if size == 0:
            return 0
        value = self.read_bits(size)
        threshold = 1 << (size - 1)
        if value < threshold:
            value -= (1 << size) - 1
        return value

    def decode_symbol(self, table: dict[tuple[int, int], int]) -> int:
        code = 0
        for bit_length in range(1, 17):
            code = (code << 1) | self.read_bit()
            symbol = table.get((bit_length, code))
            if symbol is not None:
                return symbol
        raise ValueError("JPEG Huffman 解码失败")


def _encode_jpeg_entropy(image: _JpegDctImage) -> bytes:
    writer = _EntropyBitWriter()
    mcus_x = (image.width + 8 * image.max_h - 1) // (8 * image.max_h)
    mcus_y = (image.height + 8 * image.max_v - 1) // (8 * image.max_v)
    dc_previous = {component["id"]: 0 for component in image.components}
    component_index = {component["id"]: index for index, component in enumerate(image.components)}
    for mcu_y in range(mcus_y):
        for mcu_x in range(mcus_x):
            for scan_component in image.scan_components:
                for block_y in range(scan_component["v"]):
                    for block_x in range(scan_component["h"]):
                        index = component_index[scan_component["id"]]
                        out_y = mcu_y * scan_component["v"] + block_y
                        out_x = mcu_x * scan_component["h"] + block_x
                        try:
                            row = image.coefficients[index][out_y]
                            block = row[out_x * 64 : out_x * 64 + 64]
                        except IndexError as error:
                            raise ValueError("JPEG DCT 系数矩阵与采样结构不匹配") from error
                        if len(block) != 64:
                            raise ValueError("JPEG DCT block 不完整")
                        dc_value = block[0]
                        _encode_jpeg_block(
                            writer,
                            block,
                            dc_value - dc_previous[scan_component["id"]],
                            image.huffman_encode[(0, scan_component["dc"])],
                            image.huffman_encode[(1, scan_component["ac"])],
                        )
                        dc_previous[scan_component["id"]] = dc_value
    return writer.finish()


def _encode_jpeg_block(
    writer: _EntropyBitWriter,
    block: list[int],
    dc_diff: int,
    dc_table: dict[int, tuple[int, int]],
    ac_table: dict[int, tuple[int, int]],
) -> None:
    dc_size, dc_bits = _jpeg_magnitude_bits(dc_diff)
    writer.write_huffman(dc_table, dc_size)
    if dc_size:
        writer.write_bits(dc_bits, dc_size)
    zero_run = 0
    for zigzag_index in range(1, 64):
        value = block[JPEG_ZIGZAG[zigzag_index]]
        if value == 0:
            zero_run += 1
            continue
        while zero_run >= 16:
            writer.write_huffman(ac_table, 0xF0)
            zero_run -= 16
        size, bits = _jpeg_magnitude_bits(value)
        writer.write_huffman(ac_table, (zero_run << 4) | size)
        writer.write_bits(bits, size)
        zero_run = 0
    if zero_run:
        writer.write_huffman(ac_table, 0)


def _jpeg_magnitude_bits(value: int) -> tuple[int, int]:
    if value == 0:
        return 0, 0
    size = abs(value).bit_length()
    if value > 0:
        return size, value
    return size, ((1 << size) - 1) + value


class _EntropyBitWriter:
    def __init__(self) -> None:
        self.out = bytearray()
        self.buffer = 0
        self.count = 0

    def write_huffman(self, table: dict[int, tuple[int, int]], symbol: int) -> None:
        try:
            bit_length, code = table[symbol]
        except KeyError as error:
            raise ValueError(f"JPEG Huffman 表缺少符号 0x{symbol:02x}") from error
        self.write_bits(code, bit_length)

    def write_bits(self, value: int, count: int) -> None:
        for shift in range(count - 1, -1, -1):
            self.buffer = (self.buffer << 1) | ((value >> shift) & 1)
            self.count += 1
            if self.count == 8:
                self.out.append(self.buffer)
                if self.buffer == 0xFF:
                    self.out.append(0)
                self.buffer = 0
                self.count = 0

    def finish(self) -> bytes:
        if self.count:
            self.buffer = (self.buffer << (8 - self.count)) | ((1 << (8 - self.count)) - 1)
            self.out.append(self.buffer)
            if self.buffer == 0xFF:
                self.out.append(0)
            self.buffer = 0
            self.count = 0
        return bytes(self.out)
