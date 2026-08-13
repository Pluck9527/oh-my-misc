from __future__ import annotations

import math
import re
import wave
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np
from PIL import Image

OutputFormat = Literal["bytes", "bits", "text"]
ByteOrder = Literal["msb", "lsb"]
ImageMode = Literal["rgba16stereo", "rgb16mono", "gray8"]

_FLAG_RE = re.compile(rb"flag\{[^\r\n\x00}]{0,200}\}", re.IGNORECASE)
_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("zip", b"PK\x03\x04"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("pdf", b"%PDF-"),
    ("gif", b"GIF"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
)

DEFAULT_FREQ_CHAR_MAP: dict[str, float] = {
    **{chr(ord("a") + i): freq for i, freq in enumerate((440, 466, 494, 523, 554, 587, 622, 659, 698, 740, 784, 830, 880, 932, 988, 1047, 1109, 1175, 1245, 1319, 1397, 1480, 1568, 1661, 1760, 1865))},
    **{str(i): float(i * 1000) for i in range(1, 10)},
    "0": 10_000.0,
    **{chr(ord("A") + i): freq for i, freq in enumerate((445, 471, 499, 528, 559, 592, 627, 664, 703, 745, 789, 835, 885, 937, 993, 1052, 1114, 1180, 1250, 1324, 1402, 1485, 1573, 1666, 1765, 1870))},
}


@dataclass(frozen=True)
class WavDataResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    sample_rate: int
    channels: int
    sample_width: int
    bits_per_sample: int
    frames: int
    samples: int
    duration_seconds: float
    mode: str
    bit_count: int = 0
    byte_count: int = 0
    written_bytes: int = 0
    decoded_text: str = ""
    findings: list[dict[str, Any]] | None = None
    entries: list[dict[str, Any]] | None = None
    width: int | None = None
    height: int | None = None
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _WavSamples:
    int_data: np.ndarray
    float_data: np.ndarray
    sample_rate: int
    channels: int
    sample_width: int
    frames: int

    @property
    def bits_per_sample(self) -> int:
        return self.sample_width * 8

    @property
    def duration_seconds(self) -> float:
        return self.frames / self.sample_rate if self.sample_rate else 0.0


def info_wavdata(input_path: Path) -> WavDataResult:
    wav = _read_wav_samples(input_path)
    return _result(
        "audio.wavdata.info",
        input_path,
        None,
        wav,
        mode="info",
        entries=[
            {
                "channels": wav.channels,
                "sample_width": wav.sample_width,
                "bits_per_sample": wav.bits_per_sample,
                "sample_rate": wav.sample_rate,
                "frames": wav.frames,
                "duration_seconds": wav.duration_seconds,
            }
        ],
    )


def extract_wav_lsb(
    input_path: Path,
    output_path: Path,
    *,
    bit: int = 0,
    bits: list[int] | None = None,
    channel: str = "all",
    sample_step: int = 1,
    byte_order: ByteOrder = "msb",
    output_format: OutputFormat = "bytes",
    limit_bits: int | None = None,
) -> WavDataResult:
    wav = _read_wav_samples(input_path)
    selected = _select_channels(wav.int_data, channel)
    bit_positions = bits if bits is not None else [bit]
    for item in bit_positions:
        if item < 0 or item >= wav.bits_per_sample:
            raise ValueError(f"bit 超出采样位宽：{item}")
    if sample_step <= 0:
        raise ValueError("sample_step 必须大于 0")
    selected = selected[::sample_step]
    bit_stream: list[int] = []
    for sample in selected.reshape(-1):
        value = int(sample)
        for bit_pos in bit_positions:
            bit_stream.append((value >> bit_pos) & 1)
            if limit_bits is not None and len(bit_stream) >= limit_bits:
                break
        if limit_bits is not None and len(bit_stream) >= limit_bits:
            break
    payload, decoded_text = _format_bits(bit_stream, output_format=output_format, byte_order=byte_order)
    written = _write_output(output_path, payload)
    return _result(
        "audio.wavdata.lsb",
        input_path,
        output_path,
        wav,
        mode="lsb",
        bit_count=len(bit_stream),
        byte_count=len(payload),
        written_bytes=written,
        decoded_text=decoded_text,
        findings=_find_hints(payload),
        entries=[{"channel": channel, "bits": bit_positions, "sample_step": sample_step}],
    )


def extract_channel_diff(
    input_path: Path,
    output_path: Path,
    *,
    mapping: dict[str, str],
    left_channel: int = 0,
    right_channel: int = 1,
    byte_order: ByteOrder = "msb",
    output_format: OutputFormat = "bits",
) -> WavDataResult:
    wav = _read_wav_samples(input_path)
    if wav.channels <= max(left_channel, right_channel):
        raise ValueError("channel-diff 需要对应的左右声道")
    bits_text = ""
    entries: list[dict[str, Any]] = []
    left = wav.int_data[:, left_channel]
    right = wav.int_data[:, right_channel]
    for index, (l_value, r_value) in enumerate(zip(left, right, strict=False)):
        diff = str(int(l_value) - int(r_value))
        if diff in mapping:
            bits_text += mapping[diff]
            entries.append({"index": index, "diff": int(diff), "bits": mapping[diff]})
    bit_stream = [1 if char == "1" else 0 for char in bits_text if char in "01"]
    payload, decoded_text = _format_bits(bit_stream, output_format=output_format, byte_order=byte_order)
    written = _write_output(output_path, payload)
    return _result(
        "audio.wavdata.channel-diff",
        input_path,
        output_path,
        wav,
        mode="channel-diff",
        bit_count=len(bit_stream),
        byte_count=len(payload),
        written_bytes=written,
        decoded_text=decoded_text,
        findings=_find_hints(payload),
        entries=entries[:50],
    )


def fft_map_wavdata(
    input_path: Path,
    output_path: Path,
    *,
    freqs: list[float],
    alphabet: str,
    chunk_ms: float = 100.0,
    group_size: int = 2,
    threshold: float | None = None,
    channel: str = "left",
) -> WavDataResult:
    wav = _read_wav_samples(input_path)
    mono = _channel_float(wav, channel)
    chunk_size = max(1, round(wav.sample_rate * chunk_ms / 1000.0))
    if group_size <= 0:
        raise ValueError("group-size 必须大于 0")
    indexes: list[int] = []
    entries: list[dict[str, Any]] = []
    for chunk_index, chunk in enumerate(_chunks(mono, chunk_size)):
        detected = _detect_freq_index(chunk, wav.sample_rate, freqs, threshold)
        if detected is None:
            continue
        index, freq, power = detected
        indexes.append(index)
        entries.append({"chunk": chunk_index, "index": index, "frequency": freq, "power": power})
    chars: list[str] = []
    for start in range(0, len(indexes), group_size):
        group = indexes[start : start + group_size]
        if len(group) != group_size:
            continue
        table_index = int("".join(str(item) for item in group)) if group_size > 1 else group[0]
        if 0 <= table_index < len(alphabet):
            chars.append(alphabet[table_index])
    decoded_text = "".join(chars)
    payload = decoded_text.encode("utf-8")
    written = _write_output(output_path, payload)
    return _result(
        "audio.wavdata.fft-map",
        input_path,
        output_path,
        wav,
        mode="fft-map",
        bit_count=0,
        byte_count=len(payload),
        written_bytes=written,
        decoded_text=decoded_text,
        findings=_find_hints(payload),
        entries=entries[:200],
    )


def compare_wavdata(
    first_path: Path,
    second_path: Path,
    output_path: Path,
    *,
    scale: float = 1.0,
    mapping: dict[str, str],
    channel: str = "left",
    samples: int | None = None,
    byte_order: ByteOrder = "msb",
    output_format: OutputFormat = "bytes",
) -> WavDataResult:
    first = _read_wav_samples(first_path)
    second = _read_wav_samples(second_path)
    a = _channel_float(first, channel)
    b = _channel_float(second, channel)
    length = min(len(a), len(b), samples if samples is not None else min(len(a), len(b)))
    bits_text = ""
    entries: list[dict[str, Any]] = []
    for index in range(length):
        diff = str(round((float(a[index]) - float(b[index])) * scale))
        if diff in mapping:
            bits_text += mapping[diff]
            entries.append({"index": index, "diff": int(diff), "bits": mapping[diff]})
    bit_stream = [1 if char == "1" else 0 for char in bits_text if char in "01"]
    payload, decoded_text = _format_bits(bit_stream, output_format=output_format, byte_order=byte_order)
    written = _write_output(output_path, payload)
    result = _result(
        "audio.wavdata.compare",
        first_path,
        output_path,
        first,
        mode="compare",
        bit_count=len(bit_stream),
        byte_count=len(payload),
        written_bytes=written,
        decoded_text=decoded_text,
        findings=_find_hints(payload),
        entries=entries[:50],
    )
    return WavDataResult(**{**asdict(result), "input_path": f"{first_path},{second_path}"})


def wavdata_to_image(
    input_path: Path,
    output_path: Path,
    *,
    width: int,
    height: int,
    stride: int = 1,
    offset: int = 0,
    mode: ImageMode = "rgba16stereo",
) -> WavDataResult:
    wav = _read_wav_samples(input_path)
    if width <= 0 or height <= 0:
        raise ValueError("width/height 必须大于 0")
    if stride <= 0:
        raise ValueError("stride 必须大于 0")
    need = offset + (width * height - 1) * stride + 1
    if need > wav.frames:
        raise ValueError(f"采样不足：需要 frame {need}，实际 {wav.frames}")
    image = Image.new("RGBA" if mode == "rgba16stereo" else "RGB" if mode == "rgb16mono" else "L", (width, height))
    for y in range(height):
        for x in range(width):
            sample_index = offset + (x + y * width) * stride
            if mode == "rgba16stereo":
                if wav.channels < 2:
                    raise ValueError("rgba16stereo 需要双声道 WAV")
                left = int(wav.int_data[sample_index, 0]) & 0xFFFF
                right = int(wav.int_data[sample_index, 1]) & 0xFFFF
                pixel = ((left >> 8) & 0xFF, left & 0xFF, (right >> 8) & 0xFF, right & 0xFF)
            elif mode == "rgb16mono":
                value = int(wav.int_data[sample_index, 0]) & 0xFFFFFF
                pixel = ((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)
            else:
                pixel = int(wav.int_data[sample_index, 0]) & 0xFF
            image.putpixel((x, y), pixel)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)
    written = output_path.stat().st_size
    return _result(
        "audio.wavdata.to-image",
        input_path,
        output_path,
        wav,
        mode=mode,
        written_bytes=written,
        width=width,
        height=height,
        entries=[{"stride": stride, "offset": offset, "mode": mode}],
    )


def freq_chars_wavdata(
    input_path: Path,
    output_path: Path,
    *,
    freq_map: dict[str, float] | None = None,
    chunk_ms: float = 100.0,
    tolerance: float = 30.0,
    dedupe: bool = True,
    channel: str = "left",
) -> WavDataResult:
    wav = _read_wav_samples(input_path)
    mapping = freq_map or DEFAULT_FREQ_CHAR_MAP
    mono = _channel_float(wav, channel)
    chunk_size = max(1, round(wav.sample_rate * chunk_ms / 1000.0))
    entries: list[dict[str, Any]] = []
    chars: list[str] = []
    last_char: str | None = None
    for chunk_index, chunk in enumerate(_chunks(mono, chunk_size)):
        peak = _dominant_frequency(chunk, wav.sample_rate)
        if peak is None:
            continue
        freq, power = peak
        char, diff = _closest_freq_char(freq, mapping)
        if char is None or diff > tolerance:
            entries.append({"chunk": chunk_index, "frequency": freq, "power": power, "char": None})
            continue
        if not dedupe or char != last_char:
            chars.append(char)
        last_char = char
        entries.append({"chunk": chunk_index, "frequency": freq, "power": power, "char": char})
    decoded_text = "".join(chars)
    payload = decoded_text.encode("utf-8")
    written = _write_output(output_path, payload)
    return _result(
        "audio.wavdata.freq-chars",
        input_path,
        output_path,
        wav,
        mode="freq-chars",
        byte_count=len(payload),
        written_bytes=written,
        decoded_text=decoded_text,
        findings=_find_hints(payload),
        entries=entries[:200],
    )


def _read_wav_samples(path: Path) -> _WavSamples:
    with wave.open(str(path), "rb") as wav:
        channels = wav.getnchannels()
        sample_width = wav.getsampwidth()
        sample_rate = wav.getframerate()
        frames = wav.getnframes()
        raw = wav.readframes(frames)
    ints = _pcm_to_int(raw, sample_width)
    if len(ints) % channels:
        ints = ints[: len(ints) - (len(ints) % channels)]
    int_data = ints.reshape(-1, channels)
    scale = float(1 << (sample_width * 8 - 1)) if sample_width > 1 else 128.0
    if sample_width == 1:
        float_data = (int_data.astype(np.float64) - 128.0) / 128.0
    else:
        float_data = int_data.astype(np.float64) / scale
    return _WavSamples(int_data, float_data, sample_rate, channels, sample_width, len(int_data))


def _pcm_to_int(raw: bytes, sample_width: int) -> np.ndarray:
    if sample_width == 1:
        return np.frombuffer(raw, dtype=np.uint8).astype(np.int32)
    if sample_width == 2:
        return np.frombuffer(raw, dtype="<i2").astype(np.int32)
    if sample_width == 3:
        triples = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        values = (
            triples[:, 0].astype(np.int32)
            | (triples[:, 1].astype(np.int32) << 8)
            | (triples[:, 2].astype(np.int32) << 16)
        )
        return np.where(values & 0x800000, values - 0x1000000, values).astype(np.int32)
    if sample_width == 4:
        return np.frombuffer(raw, dtype="<i4").astype(np.int64)
    raise ValueError(f"不支持的 WAV sample width：{sample_width}")


def _select_channels(data: np.ndarray, channel: str) -> np.ndarray:
    if channel == "all":
        return data
    index = _channel_index(channel)
    if index >= data.shape[1]:
        raise ValueError(f"声道不存在：{channel}")
    return data[:, index : index + 1]


def _channel_float(wav: _WavSamples, channel: str) -> np.ndarray:
    if channel in {"all", "mono", "mix"}:
        return wav.float_data.mean(axis=1)
    index = _channel_index(channel)
    if index >= wav.channels:
        raise ValueError(f"声道不存在：{channel}")
    return wav.float_data[:, index]


def _channel_index(channel: str) -> int:
    lowered = channel.lower()
    if lowered in {"left", "l"}:
        return 0
    if lowered in {"right", "r"}:
        return 1
    try:
        index = int(lowered)
    except ValueError as exc:
        raise ValueError(f"未知声道：{channel}") from exc
    if index < 0:
        raise ValueError(f"声道索引不能为负：{channel}")
    return index


def _format_bits(bits: list[int], *, output_format: OutputFormat, byte_order: ByteOrder) -> tuple[bytes, str]:
    if output_format == "bits":
        text = "".join(str(bit) for bit in bits)
        return text.encode("ascii"), text
    payload = _bits_to_bytes(bits, byte_order=byte_order)
    if output_format == "text":
        text = payload.decode("utf-8", "replace")
        return text.encode("utf-8"), text
    return payload, payload.decode("utf-8", "replace")


def _bits_to_bytes(bits: list[int], *, byte_order: ByteOrder) -> bytes:
    out = bytearray()
    usable = len(bits) - (len(bits) % 8)
    for index in range(0, usable, 8):
        chunk = bits[index : index + 8]
        value = 0
        if byte_order == "msb":
            for bit in chunk:
                value = (value << 1) | (bit & 1)
        else:
            for shift, bit in enumerate(chunk):
                value |= (bit & 1) << shift
        out.append(value)
    return bytes(out)


def _chunks(data: np.ndarray, chunk_size: int):
    for start in range(0, len(data) - chunk_size + 1, chunk_size):
        yield data[start : start + chunk_size]


def _detect_freq_index(
    chunk: np.ndarray,
    sample_rate: int,
    freqs: list[float],
    threshold: float | None,
) -> tuple[int, float, float] | None:
    if len(chunk) == 0:
        return None
    spectrum = np.abs(np.fft.rfft(chunk * np.hamming(len(chunk))))
    freq_bins = np.fft.rfftfreq(len(chunk), 1.0 / sample_rate)
    powers: list[float] = []
    for freq in freqs:
        center = int(np.argmin(np.abs(freq_bins - freq)))
        left = max(1, center - 2)
        right = min(len(spectrum), center + 3)
        powers.append(float(np.max(spectrum[left:right])))
    if not powers:
        return None
    max_power = max(powers)
    if threshold is not None and max_power < threshold:
        return None
    index = int(np.argmax(powers))
    return index, float(freqs[index]), max_power


def _dominant_frequency(chunk: np.ndarray, sample_rate: int) -> tuple[float, float] | None:
    if len(chunk) < 2:
        return None
    spectrum = np.abs(np.fft.rfft(chunk * np.hamming(len(chunk))))
    if len(spectrum) <= 1:
        return None
    spectrum[0] = 0.0
    index = int(np.argmax(spectrum))
    freq_bins = np.fft.rfftfreq(len(chunk), 1.0 / sample_rate)
    return float(freq_bins[index]), float(spectrum[index])


def _closest_freq_char(freq: float, mapping: dict[str, float]) -> tuple[str | None, float]:
    if not mapping:
        return None, math.inf
    char = min(mapping, key=lambda item: abs(mapping[item] - freq))
    return char, abs(mapping[char] - freq)


def _write_output(output_path: Path, payload: bytes) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return len(payload)


def _result(
    operation: str,
    input_path: Path,
    output_path: Path | None,
    wav: _WavSamples,
    *,
    mode: str,
    bit_count: int = 0,
    byte_count: int = 0,
    written_bytes: int = 0,
    decoded_text: str = "",
    findings: list[dict[str, Any]] | None = None,
    entries: list[dict[str, Any]] | None = None,
    width: int | None = None,
    height: int | None = None,
) -> WavDataResult:
    return WavDataResult(
        operation=operation,
        input_path=str(input_path),
        output_path=str(output_path) if output_path is not None else "-",
        output_paths=[str(output_path)] if output_path is not None else [],
        sample_rate=wav.sample_rate,
        channels=wav.channels,
        sample_width=wav.sample_width,
        bits_per_sample=wav.bits_per_sample,
        frames=wav.frames,
        samples=wav.frames * wav.channels,
        duration_seconds=wav.duration_seconds,
        mode=mode,
        bit_count=bit_count,
        byte_count=byte_count,
        written_bytes=written_bytes,
        decoded_text=decoded_text,
        findings=findings or [],
        entries=entries or [],
        width=width,
        height=height,
    )


def _find_hints(data: bytes) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for kind, signature in _SIGNATURES:
        offset = data.find(signature)
        if offset >= 0:
            findings.append({"kind": kind, "offset": offset})
    for match in _FLAG_RE.finditer(data):
        findings.append(
            {
                "kind": "flag",
                "offset": match.start(),
                "text": match.group(0).decode("utf-8", "replace"),
            }
        )
    return findings[:20]
