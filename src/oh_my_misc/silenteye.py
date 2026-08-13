from __future__ import annotations

import math
import shutil
import struct
import wave
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from PIL import Image

DataFormat = Literal["bytes", "utf8", "latin1", "ascii", "file", "unknown"]
CarrierFormat = Literal["auto", "bmp", "wav"]
Distribution = Literal["inline", "equi"]
BMPHeader = Literal["top", "bottom", "signature"]
WAVHeader = Literal["beginning", "ending"]
CryptoMode = Literal["aes128", "aes256"]
CompressMode = Literal["auto", "yes", "no"]

_DATA_PREFIX_TO_FORMAT = {
    0: "bytes",
    2: "utf8",
    3: "latin1",
    4: "ascii",
    5: "file",
}
_FORMAT_TO_DATA_PREFIX = {
    "bytes": 0,
    "utf8": 2,
    "latin1": 3,
    "ascii": 4,
    "file": 5,
}
_AES_KEYS = {
    "aes128": b"Silent Eye Encryption AES128%/.?!:;]{[}&"[:16],
    "aes256": b"Silent Eye Encryption AES256%/.?!:;]{[}&"[:32],
}
_MAGIC_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("zip", b"PK\x03\x04"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("pdf", b"%PDF-"),
    ("gif", b"GIF"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
)


@dataclass(frozen=True)
class SilentEyeResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    carrier_format: str
    data_format: str
    payload_name: str | None
    payload_bytes: int
    embedded_bytes: int
    capacity_bytes: int
    written_bytes: int
    bits: int
    channels: int | None
    colors: str | None
    distribution: str
    header_position: str
    compressed: bool
    encrypted: bool
    crypto: str | None
    width: int | None = None
    height: int | None = None
    sample_rate: int | None = None
    sample_count: int | None = None
    findings: list[dict[str, Any]] | None = None
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _ParsedData:
    format: DataFormat
    data: bytes
    name: str | None = None


def hide_silenteye(
    input_path: Path,
    output_path: Path,
    *,
    text: str | None = None,
    payload_path: Path | None = None,
    carrier: CarrierFormat = "auto",
    password: str | None = None,
    crypto: CryptoMode = "aes256",
    compress: bool = True,
    bits: int | None = None,
    channels: int | None = None,
    colors: str | None = None,
    distribution: Distribution | None = None,
    header_position: str | None = None,
) -> SilentEyeResult:
    if (text is None) == (payload_path is None):
        raise ValueError("--text 与 --payload 必须且只能提供一个")
    carrier_format = _resolve_carrier(input_path, carrier)
    if payload_path is not None:
        if not payload_path.is_file():
            raise FileNotFoundError(f"载荷不存在：{payload_path}")
        parsed = _ParsedData("file", payload_path.read_bytes(), payload_path.name)
    else:
        parsed = _ParsedData("utf8", (text or "").encode("utf-8"), None)
    formatted = _format_data(parsed)
    stored = _prepare_stored_data(formatted, password=password, crypto=crypto, compress=compress)
    if carrier_format == "wav":
        return _hide_wav(
            input_path,
            output_path,
            stored,
            parsed=parsed,
            password=password,
            crypto=crypto,
            compress=compress,
            bits=3 if bits is None else bits,
            channels=channels,
            distribution="equi" if distribution is None else distribution,
            header_position="ending" if header_position is None else header_position,
        )
    return _hide_bmp(
        input_path,
        output_path,
        stored,
        parsed=parsed,
        password=password,
        crypto=crypto,
        compress=compress,
        bits=3 if bits is None else bits,
        colors="rgb" if colors is None else colors,
        distribution="equi" if distribution is None else distribution,
        header_position="signature" if header_position is None else header_position,
    )


def extract_silenteye(
    input_path: Path,
    output_path: Path,
    *,
    carrier: CarrierFormat = "auto",
    password: str | None = None,
    crypto: CryptoMode = "aes256",
    compressed: CompressMode = "auto",
    bits: int | None = None,
    channels: int | None = None,
    colors: str | None = None,
    distribution: Distribution | None = None,
    header_position: str | None = None,
    raw: bool = False,
) -> SilentEyeResult:
    carrier_format = _resolve_carrier(input_path, carrier)
    if carrier_format == "wav":
        stored, meta = _extract_wav_stored(
            input_path,
            bits=3 if bits is None else bits,
            channels=channels,
            distribution="equi" if distribution is None else distribution,
            header_position="ending" if header_position is None else header_position,
        )
    else:
        stored, meta = _extract_bmp_stored(
            input_path,
            bits=3 if bits is None else bits,
            colors="rgb" if colors is None else colors,
            distribution="equi" if distribution is None else distribution,
            header_position="signature" if header_position is None else header_position,
        )
    parsed = _decode_stored_data(stored, password=password, crypto=crypto, compressed=compressed, raw=raw)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(parsed.data)
    return SilentEyeResult(
        operation="stego.silenteye.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format=carrier_format,
        data_format=parsed.format,
        payload_name=parsed.name,
        payload_bytes=len(parsed.data),
        embedded_bytes=len(stored),
        capacity_bytes=meta["capacity_bytes"],
        written_bytes=len(parsed.data),
        bits=meta["bits"],
        channels=meta.get("channels"),
        colors=meta.get("colors"),
        distribution=meta["distribution"],
        header_position=meta["header_position"],
        compressed=meta.get("decoded_compressed", compressed != "no"),
        encrypted=password is not None,
        crypto=crypto if password is not None else None,
        width=meta.get("width"),
        height=meta.get("height"),
        sample_rate=meta.get("sample_rate"),
        sample_count=meta.get("sample_count"),
        findings=_find_hints(parsed.data),
    )


def _prepare_stored_data(
    formatted: bytes,
    *,
    password: str | None,
    crypto: CryptoMode,
    compress: bool,
) -> bytes:
    if password is not None:
        ciphertext = _aes_encrypt(formatted, password=password, crypto=crypto)
        formatted = _format_data(_ParsedData("bytes", ciphertext, None))
    return _qcompress(formatted) if compress else formatted


def _decode_stored_data(
    stored: bytes,
    *,
    password: str | None,
    crypto: CryptoMode,
    compressed: CompressMode,
    raw: bool,
) -> _ParsedData:
    if raw:
        return _ParsedData("bytes", stored, None)
    formatted = _maybe_qdecompress(stored, compressed)
    if password is not None:
        outer = _parse_data(formatted, allow_raw=True)
        ciphertext = outer.data if outer.format == "bytes" else formatted
        plaintext = _aes_decrypt(ciphertext, password=password, crypto=crypto)
        return _parse_data(plaintext, allow_raw=False)
    return _parse_data(formatted, allow_raw=False)


def _format_data(data: _ParsedData) -> bytes:
    prefix = _FORMAT_TO_DATA_PREFIX[data.format].to_bytes(1, "big")
    prefix = bytes([prefix[0] + ord("0")])
    if data.format == "file":
        name = (data.name or "payload.bin").encode("utf-8")
        return prefix + name + b"<" + data.data
    return prefix + data.data


def _parse_data(raw: bytes, *, allow_raw: bool) -> _ParsedData:
    if not raw:
        if allow_raw:
            return _ParsedData("bytes", raw, None)
        raise ValueError("SilentEye 数据为空")
    code = raw[0] - ord("0")
    fmt = _DATA_PREFIX_TO_FORMAT.get(code)
    if fmt is None:
        if allow_raw:
            return _ParsedData("bytes", raw, None)
        raise ValueError(f"SilentEye 数据格式未知：{code}")
    payload = raw[1:]
    if fmt == "file":
        sep = payload.find(b"<")
        if sep < 0:
            raise ValueError("SilentEye 文件载荷缺少文件名分隔符")
        name = payload[:sep].decode("utf-8", errors="replace")
        return _ParsedData("file", payload[sep + 1 :], name)
    return _ParsedData(fmt, payload, None)


def _qcompress(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + zlib.compress(data, 9)


def _maybe_qdecompress(data: bytes, mode: CompressMode) -> bytes:
    if mode == "no":
        return data
    if len(data) < 6:
        if mode == "yes":
            raise ValueError("压缩 SilentEye 数据太短")
        return data
    expected = struct.unpack(">I", data[:4])[0]
    try:
        plain = zlib.decompress(data[4:])
    except zlib.error as error:
        if mode == "yes":
            raise ValueError("SilentEye qCompress 解压失败") from error
        return data
    if expected != len(plain) and mode == "yes":
        raise ValueError(f"SilentEye qCompress 长度不匹配：{len(plain)} != {expected}")
    return plain if expected == len(plain) or mode == "yes" else data


def _aes_encrypt(data: bytes, *, password: str, crypto: CryptoMode) -> bytes:
    cipher = AES.new(_AES_KEYS[crypto], AES.MODE_CBC, _silenteye_iv(password))
    return cipher.encrypt(_pkcs7_pad(data))


def _aes_decrypt(data: bytes, *, password: str, crypto: CryptoMode) -> bytes:
    if len(data) == 0 or len(data) % 16:
        raise ValueError("AES 密文长度不是 16 的倍数")
    cipher = AES.new(_AES_KEYS[crypto], AES.MODE_CBC, _silenteye_iv(password))
    return _pkcs7_unpad(cipher.decrypt(data))


def _silenteye_iv(password: str) -> bytes:
    # SilentEye builds the IV from the ASCII hex MD5 of the user key; QCA uses the AES block prefix.
    return MD5.new(password.encode("utf-8")).hexdigest().encode("ascii")[:16]


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("AES 明文为空")
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("AES PKCS7 padding 校验失败，密码或算法可能错误")
    return data[:-pad]


def _hide_bmp(
    input_path: Path,
    output_path: Path,
    stored: bytes,
    *,
    parsed: _ParsedData,
    password: str | None,
    crypto: CryptoMode,
    compress: bool,
    bits: int,
    colors: str,
    distribution: Distribution,
    header_position: str,
) -> SilentEyeResult:
    _validate_bits(bits)
    color_indices = _parse_colors(colors)
    header = _normalise_bmp_header(header_position)
    with Image.open(input_path) as source:
        image = source.convert("RGB")
    arr = np.asarray(image, dtype=np.uint8).copy()
    height, width = arr.shape[:2]
    capacity = _bmp_capacity(width, height, bits, len(color_indices))
    if len(stored) > capacity:
        raise ValueError(f"SilentEye BMP 容量不足：需要 {len(stored)} bytes，可用 {capacity} bytes")
    header_start, header_end = _bmp_header_points(width, height, bits, len(color_indices), header)
    _bmp_write_stream(arr, _uint32_le(len(stored)), bits, color_indices, header_start, 1, None)
    if header != "top":
        cursor = (0, 0)
    else:
        cursor = _bmp_after_header_cursor(width, header_end)
    step, block = _bmp_distribution(width, height, len(stored), bits, len(color_indices), distribution)
    cursor = _bmp_new_position(cursor, width, step, block, first=True)
    _bmp_write_stream(
        arr,
        stored,
        bits,
        color_indices,
        cursor,
        step,
        (header_start, header_end),
        block=block,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(arr, "RGB").save(output_path, "BMP")
    return SilentEyeResult(
        operation="stego.silenteye.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format="bmp",
        data_format=parsed.format,
        payload_name=parsed.name,
        payload_bytes=len(parsed.data),
        embedded_bytes=len(stored),
        capacity_bytes=capacity,
        written_bytes=output_path.stat().st_size,
        bits=bits,
        channels=None,
        colors=colors,
        distribution=distribution,
        header_position=header,
        compressed=compress,
        encrypted=password is not None,
        crypto=crypto if password is not None else None,
        width=width,
        height=height,
        findings=_find_hints(parsed.data),
    )


def _extract_bmp_stored(
    input_path: Path,
    *,
    bits: int,
    colors: str,
    distribution: Distribution,
    header_position: str,
) -> tuple[bytes, dict[str, Any]]:
    _validate_bits(bits)
    color_indices = _parse_colors(colors)
    header = _normalise_bmp_header(header_position)
    with Image.open(input_path) as source:
        image = source.convert("RGB")
    arr = np.asarray(image, dtype=np.uint8)
    height, width = arr.shape[:2]
    capacity = _bmp_capacity(width, height, bits, len(color_indices))
    header_start, header_end = _bmp_header_points(width, height, bits, len(color_indices), header)
    size_bytes = _bmp_read_stream(arr, 4, bits, color_indices, header_start, 1, None)
    size = int.from_bytes(size_bytes, "little")
    if size > capacity:
        raise ValueError(f"SilentEye BMP 载荷长度超过容量：{size} > {capacity}")
    cursor = (0, 0) if header != "top" else _bmp_after_header_cursor(width, header_end)
    step, block = _bmp_distribution(width, height, size, bits, len(color_indices), distribution)
    cursor = _bmp_new_position(cursor, width, step, block, first=True)
    payload = _bmp_read_stream(
        arr,
        size,
        bits,
        color_indices,
        cursor,
        step,
        (header_start, header_end),
        block=block,
    )
    return payload, {
        "capacity_bytes": capacity,
        "bits": bits,
        "colors": colors,
        "distribution": distribution,
        "header_position": header,
        "width": width,
        "height": height,
    }


def _bmp_capacity(width: int, height: int, bits: int, nb_colors: int) -> int:
    size_nb_pixel = math.ceil(32.0 / (nb_colors * bits))
    return math.floor((bits * nb_colors * ((width * height) - size_nb_pixel)) / 8.0)


def _bmp_header_points(
    width: int, height: int, bits: int, nb_colors: int, header: BMPHeader) -> tuple[tuple[int, int], tuple[int, int]]:
    head_nb_pixel = math.ceil(32.0 / (nb_colors * bits))
    start_x = 0
    start_y = 0
    if header == "bottom":
        start_x = abs(head_nb_pixel - width) % width
        start_y = height - math.ceil((start_x + head_nb_pixel - 1) / width)
    elif header == "signature":
        start_x = math.floor(width * 0.95)
        start_y = math.floor(height * 0.95)
        if ((width - start_x) + (height - start_y) * width) < head_nb_pixel:
            raise ValueError("图片太小，不能使用 SilentEye signature 头位置")
    end_x = (start_x + head_nb_pixel - 1) % width
    end_y = start_y + math.floor((start_x + head_nb_pixel - 1) / width)
    return (start_x, start_y), (end_x, end_y)


def _bmp_after_header_cursor(width: int, header_end: tuple[int, int]) -> tuple[int, int]:
    x, y = header_end
    if x == width - 1:
        return 0, y + 1
    return x + 1, y


def _bmp_distribution(
    width: int,
    height: int,
    size: int,
    bits: int,
    nb_colors: int,
    distribution: Distribution,
) -> tuple[int, dict[str, int] | None]:
    if distribution == "inline":
        return 1, None
    size_nb_pixel = math.ceil(32.0 / (nb_colors * bits))
    nb_pixel_available = (width * height) - size_nb_pixel
    nb_pixel_data = max(1, math.ceil((size * 8.0) / (nb_colors * bits)))
    step = math.floor(nb_pixel_available / nb_pixel_data)
    if step <= 0:
        step = 1
    if step < 9:
        return step, None
    square_length = math.floor(math.sqrt(step))
    if width < height:
        ratio = width / height
        ratio *= 1 / (ratio * 2)
        block_width = math.ceil(square_length * ratio)
        block_height = math.ceil(block_width / ratio)
    else:
        ratio = height / width
        ratio *= 1 / (ratio * 2)
        block_height = math.ceil(square_length * ratio)
        block_width = math.ceil(block_height / ratio)
    block_inner = min(math.floor(block_width / 2.0), math.floor(block_height / 2.0))
    return step, {"width": block_width, "height": block_height, "inner": block_inner}


def _bmp_write_stream(
    arr: np.ndarray,
    data: bytes,
    bits: int,
    color_indices: list[int],
    start: tuple[int, int],
    step: int,
    header_block: tuple[tuple[int, int], tuple[int, int]] | None,
    *,
    block: dict[str, int] | None = None,
) -> None:
    height, width = arr.shape[:2]
    chunks = _encoded_chunks(data, bits)
    chunk_index = 0
    x, y = start
    mask = 0xFF ^ ((1 << bits) - 1)
    while y < height and chunk_index < len(chunks):
        if header_block and _bmp_between((x, y), *header_block):
            x, y = _bmp_new_position(header_block[1], width, 1, None)
            continue
        for channel in color_indices:
            if chunk_index >= len(chunks):
                break
            arr[y, x, channel] = (int(arr[y, x, channel]) & mask) | chunks[chunk_index]
            chunk_index += 1
        if chunk_index < len(chunks):
            x, y = _bmp_new_position((x, y), width, step, block)
    if chunk_index < len(chunks):
        raise ValueError("SilentEye BMP 写入越界")


def _bmp_read_stream(
    arr: np.ndarray,
    size: int,
    bits: int,
    color_indices: list[int],
    start: tuple[int, int],
    step: int,
    header_block: tuple[tuple[int, int], tuple[int, int]] | None,
    *,
    block: dict[str, int] | None = None,
) -> bytes:
    height, width = arr.shape[:2]
    needed_chunks = math.ceil(size * 8 / bits) if size else 0
    values: list[int] = []
    x, y = start
    mask = (1 << bits) - 1
    while y < height and len(values) < needed_chunks:
        if header_block and _bmp_between((x, y), *header_block):
            x, y = _bmp_new_position(header_block[1], width, 1, None)
            continue
        for channel in color_indices:
            if len(values) >= needed_chunks:
                break
            values.append(int(arr[y, x, channel]) & mask)
        if len(values) < needed_chunks:
            x, y = _bmp_new_position((x, y), width, step, block)
    return _chunks_to_bytes(values, bits)[:size]


def _bmp_new_position(
    old: tuple[int, int], width: int, step: int, block: dict[str, int] | None, first: bool = False) -> tuple[int, int]:
    x, y = old
    if first:
        if block is not None:
            return block["inner"], block["inner"]
        return x, y
    new_x = x + (block["width"] if block is not None else step)
    if new_x >= width:
        y += block["height"] if block is not None else math.floor(new_x / width)
    return new_x % width, y


def _bmp_between(ref: tuple[int, int], start: tuple[int, int], end: tuple[int, int]) -> bool:
    x, y = ref
    sx, sy = start
    ex, ey = end
    if sy == ey:
        return y == sy and sx <= x <= ex
    return (y == sy and x >= sx) or (y == ey and x <= ex) or (sy < y < ey)


def _hide_wav(
    input_path: Path,
    output_path: Path,
    stored: bytes,
    *,
    parsed: _ParsedData,
    password: str | None,
    crypto: CryptoMode,
    compress: bool,
    bits: int,
    channels: int | None,
    distribution: Distribution,
    header_position: str,
) -> SilentEyeResult:
    meta, samples, params = _read_wav_samples(input_path)
    _validate_bits(bits)
    used_channels = _normalise_channels(channels, meta["channels"])
    header = _normalise_wav_header(header_position)
    capacity = math.floor(meta["sample_count"] * used_channels * bits / 8.0)
    if len(stored) > capacity:
        raise ValueError(f"SilentEye WAV 容量不足：需要 {len(stored)} bytes，可用 {capacity} bytes")
    encoded = samples.copy()
    header_samples = math.ceil(32.0 / (used_channels * bits))
    header_index = 0 if header == "beginning" else meta["sample_count"] - header_samples
    _wav_write_stream(encoded, _uint32_le(len(stored)), bits, used_channels, header_index, 1)
    data_index = header_samples if header == "beginning" else 0
    step = _wav_distribution(meta["sample_count"], len(stored), bits, used_channels, distribution)
    _wav_write_stream(
        encoded,
        stored,
        bits,
        used_channels,
        data_index,
        step,
        stop_before=meta["sample_count"] - header_samples if header == "ending" else None,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(output_path), "wb") as out:
        out.setparams(params)
        out.writeframes(_samples_to_frames(encoded, meta))
    return SilentEyeResult(
        operation="stego.silenteye.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format="wav",
        data_format=parsed.format,
        payload_name=parsed.name,
        payload_bytes=len(parsed.data),
        embedded_bytes=len(stored),
        capacity_bytes=capacity,
        written_bytes=output_path.stat().st_size,
        bits=bits,
        channels=used_channels,
        colors=None,
        distribution=distribution,
        header_position=header,
        compressed=compress,
        encrypted=password is not None,
        crypto=crypto if password is not None else None,
        sample_rate=meta["sample_rate"],
        sample_count=meta["sample_count"],
        findings=_find_hints(parsed.data),
    )


def _extract_wav_stored(
    input_path: Path,
    *,
    bits: int,
    channels: int | None,
    distribution: Distribution,
    header_position: str,
) -> tuple[bytes, dict[str, Any]]:
    meta, samples, _params = _read_wav_samples(input_path)
    _validate_bits(bits)
    used_channels = _normalise_channels(channels, meta["channels"])
    header = _normalise_wav_header(header_position)
    capacity = math.floor(meta["sample_count"] * used_channels * bits / 8.0)
    header_samples = math.ceil(32.0 / (used_channels * bits))
    header_index = 0 if header == "beginning" else meta["sample_count"] - header_samples
    size_bytes = _wav_read_stream(samples, 4, bits, used_channels, header_index, 1)
    size = int.from_bytes(size_bytes, "little")
    if size > capacity:
        raise ValueError(f"SilentEye WAV 载荷长度超过容量：{size} > {capacity}")
    data_index = header_samples if header == "beginning" else 0
    step = _wav_distribution(meta["sample_count"], size, bits, used_channels, distribution)
    payload = _wav_read_stream(samples, size, bits, used_channels, data_index, step)
    return payload, {
        "capacity_bytes": capacity,
        "bits": bits,
        "channels": used_channels,
        "distribution": distribution,
        "header_position": header,
        "sample_rate": meta["sample_rate"],
        "sample_count": meta["sample_count"],
    }


def _read_wav_samples(input_path: Path) -> tuple[dict[str, int], np.ndarray, wave._wave_params]:
    if not input_path.is_file():
        raise FileNotFoundError(f"WAV 文件不存在：{input_path}")
    with wave.open(str(input_path), "rb") as wav:
        params = wav.getparams()
        channels = wav.getnchannels()
        sample_width = wav.getsampwidth()
        if sample_width not in {1, 2}:
            raise ValueError("SilentEye WAV 兼容模式仅支持 8-bit 或 16-bit PCM")
        frames = wav.readframes(wav.getnframes())
    if sample_width == 1:
        values = np.frombuffer(frames, dtype=np.uint8).astype(np.uint16)
    else:
        # SilentEye's Qt path reads RIFF sample words as big-endian; preserve that behavior.
        values = np.frombuffer(frames, dtype=">u2").astype(np.uint16)
    sample_count = len(values) // channels
    samples = values[: sample_count * channels].reshape(sample_count, channels).copy()
    return {
        "channels": channels,
        "sample_width": sample_width,
        "sample_rate": params.framerate,
        "sample_count": sample_count,
    }, samples, params


def _samples_to_frames(samples: np.ndarray, meta: dict[str, int]) -> bytes:
    if meta["sample_width"] == 1:
        return samples.astype(np.uint8).tobytes()
    return samples.astype(">u2").tobytes()


def _wav_distribution(sample_count: int, size: int, bits: int, channels: int, distribution: Distribution) -> int:
    if distribution == "inline" or size == 0:
        return 1
    needed = max(1, math.ceil((size * 8.0) / (channels * bits)))
    return max(1, math.floor(sample_count / needed))


def _wav_write_stream(
    samples: np.ndarray,
    data: bytes,
    bits: int,
    channels: int,
    start_index: int,
    step: int,
    stop_before: int | None = None,
) -> None:
    chunks = _encoded_chunks(data, bits)
    chunk_index = 0
    index = start_index
    mask = 0xFFFF ^ ((1 << bits) - 1)
    limit = samples.shape[0] if stop_before is None else stop_before
    while index < limit and chunk_index < len(chunks):
        for channel in range(channels):
            if chunk_index >= len(chunks):
                break
            samples[index, channel] = (int(samples[index, channel]) & mask) | chunks[chunk_index]
            chunk_index += 1
        index += step
    if chunk_index < len(chunks):
        raise ValueError("SilentEye WAV 写入越界")


def _wav_read_stream(samples: np.ndarray, size: int, bits: int, channels: int, start_index: int, step: int) -> bytes:
    needed_chunks = math.ceil(size * 8 / bits) if size else 0
    values: list[int] = []
    index = start_index
    mask = (1 << bits) - 1
    while index < samples.shape[0] and len(values) < needed_chunks:
        for channel in range(channels):
            if len(values) >= needed_chunks:
                break
            values.append(int(samples[index, channel]) & mask)
        index += step
    return _chunks_to_bytes(values, bits)[:size]


def _encoded_chunks(data: bytes, bits: int) -> list[int]:
    mask = (1 << bits) - 1
    chunks: list[int] = []
    if not data:
        return chunks
    array_count = 0
    bit_count = 0
    car = data[0]
    while array_count < len(data):
        bits_left = 8 - bit_count
        if bits_left < bits:
            val = car & ((1 << bits_left) - 1)
            bits_remaining = bits - bits_left
            if array_count < len(data) - 1:
                car = data[array_count + 1]
                val += (car & ((1 << bits_remaining) - 1)) << bits_left
                car >>= bits_remaining
                bit_count = bits_remaining
            array_count += 1
        else:
            val = car & mask
            if bit_count + bits >= 8:
                bit_count = 0
                if array_count < len(data) - 1:
                    car = data[array_count + 1]
                array_count += 1
            else:
                car >>= bits
                bit_count += bits
        chunks.append(val)
    return chunks


def _chunks_to_bytes(values: list[int], bits: int) -> bytes:
    output = bytearray()
    bit_count = 0
    car = 0
    for val in values:
        bits_left = 8 - bit_count
        temp_val = val
        if bits_left < bits:
            val &= (1 << bits_left) - 1
        car += val << bit_count
        if bit_count + bits >= 8:
            output.append(car & 0xFF)
            bit_count = 0
            car = 0
        else:
            bit_count += bits
        if bits_left < bits:
            bits_remaining = bits - bits_left
            car += temp_val >> bits_left
            bit_count += bits_remaining
    return bytes(output)


def _uint32_le(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def _resolve_carrier(path: Path, carrier: CarrierFormat) -> Literal["bmp", "wav"]:
    if carrier != "auto":
        return carrier
    suffix = path.suffix.lower()
    if suffix == ".wav":
        return "wav"
    if suffix in {".bmp", ".png", ".jpg", ".jpeg"}:
        return "bmp"
    raise ValueError("无法自动判断 SilentEye 载体，请指定 --carrier wav 或 --carrier bmp")


def _validate_bits(bits: int) -> None:
    if bits < 1 or bits > 6:
        raise ValueError("SilentEye bits 必须在 1..6")


def _parse_colors(colors: str) -> list[int]:
    mapping = {"r": 0, "g": 1, "b": 2}
    result: list[int] = []
    for char in colors.lower():
        if char not in mapping:
            raise ValueError("colors 只能包含 r/g/b，例如 rgb 或 b")
        if mapping[char] not in result:
            result.append(mapping[char])
    if not result:
        raise ValueError("colors 不能为空")
    return result


def _normalise_channels(channels: int | None, total: int) -> int:
    used = total if channels is None else channels
    if used <= 0 or used > total:
        raise ValueError(f"channels 必须在 1..{total}")
    return used


def _normalise_bmp_header(value: str) -> BMPHeader:
    lowered = value.lower()
    if lowered not in {"top", "bottom", "signature"}:
        raise ValueError("BMP header-position 必须是 top/bottom/signature")
    return lowered  # type: ignore[return-value]


def _normalise_wav_header(value: str) -> WAVHeader:
    lowered = value.lower()
    if lowered not in {"beginning", "ending"}:
        raise ValueError("WAV header-position 必须是 beginning/ending")
    return lowered  # type: ignore[return-value]


def _find_hints(payload: bytes) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    window = payload[:4096]
    for kind, magic in _MAGIC_SIGNATURES:
        offset = window.find(magic)
        if offset >= 0:
            findings.append({"kind": kind, "offset": offset})
    if b"flag{" in window.lower():
        start = window.lower().find(b"flag{")
        end = window.find(b"}", start)
        if end > start:
            findings.append({"kind": "flag", "offset": start, "text": window[start : end + 1].decode(errors="replace")})
    return findings
