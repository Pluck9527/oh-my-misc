from __future__ import annotations

import hashlib
import wave
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

from Crypto.Cipher import AES, Blowfish


@dataclass(frozen=True)
class SteghideResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    tool_path: str
    password_used: bool
    backend: str = "native"
    carrier_format: str = ""
    embedded_name: str = ""
    encrypted: bool = False
    compressed: bool = False
    checksum_ok: bool | None = None
    found_password: str | None = None
    attempts: int = 0
    written_bytes: int = 0
    stdout: str = ""
    stderr: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _NativeSteghidePayload:
    data: bytes
    carrier_format: str
    embedded_name: str
    encrypted: bool
    compressed: bool
    checksum_ok: bool | None


def extract_steghide(
    input_path: Path,
    output_path: Path,
    *,
    password: str = "",
    steghide_path: Path | None = None,
    backend: str = "auto",
) -> SteghideResult:
    """Extract a steghide payload with the native Python backend."""

    _check_file(input_path, "宿主文件")
    _check_backend(backend)
    _ = steghide_path
    payload = extract_steghide_native(input_path, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload.data)
    return SteghideResult(
        operation="image.steghide.extract-native",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        tool_path="python",
        backend="native",
        carrier_format=payload.carrier_format,
        embedded_name=payload.embedded_name,
        password_used=bool(password),
        found_password=password if password else "",
        attempts=1,
        written_bytes=len(payload.data),
        encrypted=payload.encrypted,
        compressed=payload.compressed,
        checksum_ok=payload.checksum_ok,
    )


def brute_steghide(
    input_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    steghide_path: Path | None = None,
    contains: bytes | None = None,
    prefix: bytes | None = None,
    include_empty: bool = True,
    backend: str = "auto",
) -> SteghideResult:
    """Try steghide passphrases from a dictionary and keep the first matching payload."""

    _check_file(input_path, "宿主文件")
    _check_file(wordlist_path, "字典")
    _check_backend(backend)
    _ = steghide_path
    attempts = 0
    last_error = ""
    for candidate in _password_candidates(wordlist_path, include_empty=include_empty):
        attempts += 1
        try:
            payload = extract_steghide_native(input_path, password=candidate)
        except (OSError, ValueError) as error:
            last_error = str(error)
            continue
        if contains is not None and contains not in payload.data:
            continue
        if prefix is not None and not payload.data.startswith(prefix):
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload.data)
        return SteghideResult(
            operation="image.steghide.brute-native",
            input_path=str(input_path),
            output_path=str(output_path),
            output_paths=[str(output_path)],
            tool_path="python",
            backend="native",
            carrier_format=payload.carrier_format,
            embedded_name=payload.embedded_name,
            password_used=bool(candidate),
            found_password=candidate,
            attempts=attempts,
            written_bytes=len(payload.data),
            encrypted=payload.encrypted,
            compressed=payload.compressed,
            checksum_ok=payload.checksum_ok,
        )
    extra = f"；最后错误：{last_error}" if last_error else ""
    raise ValueError(f"steghide native 字典爆破失败，尝试 {attempts} 个密码{extra}")


def extract_steghide_native(input_path: Path, *, password: str = "") -> _NativeSteghidePayload:
    """Pure-Python steghide 0.5.x extractor for JPEG DCT and PCM WAV carriers."""

    _check_file(input_path, "宿主文件")
    values, samples_per_vertex, modulus, carrier_format = _read_native_carrier(input_path)
    data, meta = _decode_steghide_values(
        values,
        samples_per_vertex=samples_per_vertex,
        modulus=modulus,
        password=password,
    )
    return _NativeSteghidePayload(data=data, carrier_format=carrier_format, **meta)


def _decode_steghide_values(
    values: list[int],
    *,
    samples_per_vertex: int,
    modulus: int,
    password: str,
) -> tuple[bytes, dict[str, object]]:
    if modulus <= 1 or modulus & (modulus - 1):
        raise ValueError("steghide native carrier modulus must be a power of two")
    bits_per_emb_value = (modulus - 1).bit_length()
    selector = _SteghideSelector(len(values), password)
    reservoir: list[int] = []
    sample_index = 0

    def ensure(nbits: int) -> None:
        nonlocal sample_index
        while len(reservoir) < nbits:
            needed = nbits - len(reservoir)
            embvalues = (needed + bits_per_emb_value - 1) // bits_per_emb_value
            if sample_index + samples_per_vertex * embvalues >= len(values):
                raise ValueError("stego data is too short to contain embedded data")
            for _ in range(embvalues):
                emb_value = 0
                for _ in range(samples_per_vertex):
                    emb_value = (emb_value + values[selector[sample_index]]) % modulus
                    sample_index += 1
                for bit_index in range(bits_per_emb_value):
                    reservoir.append((emb_value >> bit_index) & 1)

    def read_bits(nbits: int) -> list[int]:
        ensure(nbits)
        out = reservoir[:nbits]
        del reservoir[:nbits]
        return out

    def read_value(nbits: int) -> int:
        return _bits_value(read_bits(nbits), 0, nbits)

    magic = read_value(24)
    if magic != 0x73688D:
        raise ValueError("could not extract any data with that passphrase")
    version = 0
    while read_value(1):
        version += 1
    if version > 0:
        raise ValueError(f"unsupported steghide embedding version: {version}")
    enc_algo = read_value(5)
    enc_mode = read_value(3)
    nplainbits = read_value(32)
    if nplainbits > 512 * 1024 * 1024:
        raise ValueError(f"steghide plain payload bit length is too large: {nplainbits}")
    encrypted_bits = _encrypted_size_bits(enc_algo, enc_mode, nplainbits)
    cipher_bits = read_bits(encrypted_bits)
    plain_bits = _decrypt_steghide_bits(cipher_bits, enc_algo, enc_mode, password)
    if len(plain_bits) < nplainbits:
        raise ValueError("steghide decrypted bit stream is too short")
    plain_bits = plain_bits[:nplainbits]

    pos = 0
    compressed = bool(plain_bits[pos])
    pos += 1
    if compressed:
        n_uncompressed_bits = _bits_value(plain_bits, pos, 32)
        pos += 32
        compressed_bytes = _bytes_from_bits(plain_bits[pos:])
        try:
            uncompressed = zlib.decompress(compressed_bytes)
        except zlib.error as error:
            raise ValueError("steghide compressed data is corrupted") from error
        plain_bits = _bits_from_bytes(uncompressed)[:n_uncompressed_bits]
        pos = 0

    checksum = bool(plain_bits[pos])
    pos += 1
    crc_expected = None
    if checksum:
        crc_expected = _bits_value(plain_bits, pos, 32)
        pos += 32

    filename = bytearray()
    while True:
        if pos + 8 > len(plain_bits):
            raise ValueError("steghide embedded filename is truncated")
        byte = _bits_value(plain_bits, pos, 8)
        pos += 8
        if byte == 0:
            break
        filename.append(byte)

    if (len(plain_bits) - pos) % 8:
        raise ValueError("steghide embedded data has invalid length")
    payload = _bytes_from_bits(plain_bits[pos:])
    checksum_ok: bool | None
    if crc_expected is None:
        checksum_ok = None
    else:
        crc_actual = zlib.crc32(payload) & 0xFFFFFFFF
        crc_actual_swapped = int.from_bytes(crc_actual.to_bytes(4, "big"), "little")
        checksum_ok = crc_expected in {crc_actual, crc_actual_swapped}
    return payload, {
        "embedded_name": filename.decode("utf-8", "replace"),
        "encrypted": enc_algo != 0,
        "compressed": compressed,
        "checksum_ok": checksum_ok,
    }


def _read_native_carrier(input_path: Path) -> tuple[list[int], int, int, str]:
    head = input_path.read_bytes()[:12]
    if head.startswith(b"\xff\xd8"):
        return _read_jpeg_values(input_path), 3, 2, "jpeg"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return _read_wav_values(input_path), 2, 2, "wav"
    if head.startswith(b"BM"):
        return _read_bmp_carrier(input_path)
    if head.startswith(b".snd"):
        return _read_au_values(input_path), 2, 2, "au"
    raise ValueError("steghide native backend 当前内置支持 JPEG/BMP/WAV/AU 载体")


def _is_native_supported(input_path: Path) -> bool:
    try:
        head = input_path.read_bytes()[:12]
    except OSError:
        return False
    return head.startswith((b"\xff\xd8", b"BM", b".snd")) or (
        head.startswith(b"RIFF") and head[8:12] == b"WAVE"
    )


def _read_jpeg_values(input_path: Path) -> list[int]:
    from oh_my_misc.jphs import _read_jpeg_dct_coefficients

    coefficients = _read_jpeg_dct_coefficients(input_path)
    values: list[int] = []
    for component in coefficients:
        for row in component:
            for coeff in row:
                if coeff != 0:
                    values.append(abs(coeff) & 1)
    if not values:
        raise ValueError("JPEG 没有可用于 steghide 的非零 DCT 系数")
    return values


def _read_wav_values(input_path: Path) -> list[int]:
    values: list[int] = []
    with wave.open(str(input_path), "rb") as stream:
        sample_width = stream.getsampwidth()
        frames = stream.readframes(stream.getnframes())
    if sample_width < 1 or sample_width > 4:
        raise ValueError(f"不支持的 WAV sample width: {sample_width}")
    for offset in range(0, len(frames) - sample_width + 1, sample_width):
        chunk = frames[offset : offset + sample_width]
        if sample_width == 1:
            value = chunk[0]
        else:
            value = int.from_bytes(chunk, "little", signed=True)
        values.append(value & 1)
    if not values:
        raise ValueError("WAV 没有 PCM sample 数据")
    return values


def _read_bmp_carrier(input_path: Path) -> tuple[list[int], int, int, str]:
    data = input_path.read_bytes()
    if len(data) < 26 or not data.startswith(b"BM"):
        raise ValueError("不是 BMP 文件")
    pixel_offset = int.from_bytes(data[10:14], "little")
    dib_size = int.from_bytes(data[14:18], "little")
    if dib_size == 40:
        width = int.from_bytes(data[18:22], "little", signed=True)
        height = int.from_bytes(data[22:26], "little", signed=True)
        bitcount = int.from_bytes(data[28:30], "little")
        compression = int.from_bytes(data[30:34], "little")
        if compression != 0:
            raise ValueError("steghide native BMP backend only supports uncompressed BI_RGB")
    elif dib_size == 12:
        width = int.from_bytes(data[18:20], "little")
        height = int.from_bytes(data[20:22], "little")
        bitcount = int.from_bytes(data[24:26], "little")
    else:
        raise ValueError(f"unsupported BMP DIB header size: {dib_size}")
    if width <= 0 or height == 0:
        raise ValueError("unsupported BMP dimensions")
    height_abs = abs(height)
    if bitcount not in {1, 4, 8, 24}:
        raise ValueError(f"unsupported steghide BMP bit depth: {bitcount}")
    row_bytes = (width * bitcount + 7) // 8
    stride = (row_bytes + 3) & ~3
    end = pixel_offset + stride * height_abs
    if pixel_offset < 0 or end > len(data):
        raise ValueError("BMP pixel data is truncated")
    bitmap = bytearray()
    for row in range(height_abs):
        start = pixel_offset + row * stride
        bitmap.extend(data[start : start + row_bytes])
    values: list[int] = []
    for pos in range(width * height_abs):
        row = pos // width
        column_pos = pos % width
        if bitcount in {1, 4, 8}:
            samples_per_byte = 8 // bitcount
            column = column_pos // samples_per_byte
            firstbit = (samples_per_byte - (column_pos % samples_per_byte) - 1) * bitcount
            index = row * row_bytes + column
            palette_index = (bitmap[index] >> firstbit) & ((1 << bitcount) - 1)
            modulus = 4 if bitcount == 8 else 2
            values.append(palette_index % modulus)
        else:
            index = row * row_bytes + column_pos * 3
            blue = bitmap[index]
            green = bitmap[index + 1]
            red = bitmap[index + 2]
            values.append((((red & 1) ^ (green & 1)) << 1) | ((red & 1) ^ (blue & 1)))
    if bitcount == 24:
        return values, 2, 4, "bmp"
    if bitcount == 8:
        return values, 3, 4, "bmp"
    return values, 2, 2, "bmp"


def _read_au_values(input_path: Path) -> list[int]:
    data = input_path.read_bytes()
    if len(data) < 24 or not data.startswith(b".snd"):
        raise ValueError("不是 AU/SND 文件")
    offset = int.from_bytes(data[4:8], "big")
    size = int.from_bytes(data[8:12], "big")
    encoding = int.from_bytes(data[12:16], "big")
    if offset < 24 or offset > len(data):
        raise ValueError("AU data offset is invalid")
    payload = data[offset:] if size == 0xFFFFFFFF else data[offset : offset + size]
    if encoding in {1, 2}:
        values = [byte & 1 for byte in payload]
    elif encoding == 3:
        values = [
            int.from_bytes(payload[offset : offset + 2], "big", signed=True) & 1
            for offset in range(0, len(payload) - 1, 2)
        ]
    else:
        raise ValueError(f"unsupported AU encoding for steghide native backend: {encoding}")
    if not values:
        raise ValueError("AU 没有 sample 数据")
    return values


def _encrypted_size_bits(enc_algo: int, enc_mode: int, nplainbits: int) -> int:
    if enc_algo == 0:
        return nplainbits
    spec = _cipher_spec(enc_algo, enc_mode)
    blocks = (nplainbits + spec["block_bits"] - 1) // spec["block_bits"]
    return spec["iv_bytes"] * 8 + blocks * spec["block_bits"]


def _decrypt_steghide_bits(
    cipher_bits: list[int], enc_algo: int, enc_mode: int, password: str
) -> list[int]:
    if enc_algo == 0:
        return cipher_bits
    spec = _cipher_spec(enc_algo, enc_mode)
    data = _bytes_from_bits(cipher_bits)
    iv_size = spec["iv_bytes"]
    block_bytes = spec["block_bits"] // 8
    if len(data) < iv_size or (len(data) - iv_size) % block_bytes:
        raise ValueError("steghide encrypted data has invalid block length")
    iv = data[:iv_size]
    ciphertext = data[iv_size:]
    key = _mcrypt_md5_key(password, spec["key_bytes"])
    if spec["name"] == "rijndael-128":
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    elif spec["name"] == "blowfish":
        plain = Blowfish.new(key, Blowfish.MODE_CBC, iv).decrypt(ciphertext)
    else:  # pragma: no cover - guarded by _cipher_spec
        raise ValueError(f"unsupported steghide cipher: {spec['name']}")
    return _bits_from_bytes(plain)


def _cipher_spec(enc_algo: int, enc_mode: int) -> dict[str, int | str]:
    if enc_mode != 1:
        raise ValueError(f"steghide native backend only supports CBC mode, got mode={enc_mode}")
    if enc_algo == 2:
        return {"name": "rijndael-128", "key_bytes": 16, "iv_bytes": 16, "block_bits": 128}
    if enc_algo == 16:
        return {"name": "blowfish", "key_bytes": 56, "iv_bytes": 8, "block_bits": 64}
    raise ValueError(f"steghide native backend does not support cipher id {enc_algo}")


def _mcrypt_md5_key(password: str, key_size: int) -> bytes:
    password_bytes = password.encode("utf-8")
    key = b""
    while len(key) < key_size:
        digest = hashlib.md5(password_bytes + key).digest()
        key += digest
    return key[:key_size]


class _PseudoRandomSource:
    def __init__(self, seed: int):
        self.value = seed & 0xFFFFFFFF

    def get_value(self, n: int) -> int:
        self.value = (1367208549 * self.value + 1) & 0xFFFFFFFF
        return int(float(n) * (float(self.value) / 4294967296.0))


class _SteghideSelector:
    def __init__(self, maximum: int, password: str):
        if maximum <= 0:
            raise ValueError("steghide carrier has no samples")
        digest = hashlib.md5(password.encode("utf-8")).digest()
        seed = 0
        for offset in range(0, 16, 4):
            seed ^= int.from_bytes(digest[offset : offset + 4], "little")
        self.maximum = maximum
        self.x: list[int] = []
        self.y: list[int] = []
        self.x_reversed: dict[int, int] = {}
        self.random = _PseudoRandomSource(seed)

    def __getitem__(self, index: int) -> int:
        if index >= self.maximum:
            raise IndexError(index)
        self._calculate(index + 1)
        return self.x[index]

    def _idx_x(self, value: int, end: int) -> int | None:
        found = self.x_reversed.get(value)
        if found is not None and found < end:
            return found
        return None

    def _set_x(self, index: int, value: int) -> None:
        self.x[index] = value
        self.x_reversed[value] = index

    def _calculate(self, count: int) -> None:
        start = len(self.x)
        if count > len(self.x):
            self.x.extend([0] * (count - len(self.x)))
            self.y.extend([0] * (count - len(self.y)))
        for j in range(start, count):
            k = j + self.random.get_value(self.maximum - j)
            i = self._idx_x(k, j)
            if i is not None:
                self._set_x(j, self.y[i])
                if self.x[j] > j:
                    self.y[j] = j
                if self.x[i] > j:
                    self.y[i] = j
                    linked = self._idx_x(self.y[i], j)
                    if linked is not None:
                        self.y[i] = self.y[linked]
            else:
                self._set_x(j, k)
                self.y[j] = j
            if self.x[j] > j:
                linked = self._idx_x(self.y[j], j)
                if linked is not None:
                    self.y[j] = self.y[linked]


def _bits_value(bits: list[int], start: int, length: int) -> int:
    value = 0
    for bit_index in range(length):
        value |= bits[start + bit_index] << bit_index
    return value


def _bytes_from_bits(bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:
            out[index // 8] |= 1 << (index % 8)
    return bytes(out)


def _bits_from_bytes(data: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


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


def _check_backend(backend: str) -> None:
    if backend not in {"auto", "native", "tool"}:
        raise ValueError("backend 必须是 auto、native 或 tool")


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
