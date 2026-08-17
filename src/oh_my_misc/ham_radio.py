from __future__ import annotations

import wave
from dataclasses import asdict, dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any, Literal

import numpy as np

HamMode = Literal["afsk1200"]
HamBackend = Literal["native", "multimon", "auto"]

_BIT_RATE = 1200
_NATIVE_RATE = 9600
_MARK_FREQ = 1200.0
_SPACE_FREQ = 2200.0
_FLAG_BITS = (0, 1, 1, 1, 1, 1, 1, 0)
_APRS_CONTROL = 0x03
_APRS_PID = 0xF0


@dataclass(frozen=True)
class HamRadioResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    backend: str
    sample_rate: int
    channels: int
    sample_width: int
    samples: int
    duration_seconds: float
    demod_sample_rate: int
    bit_rate: int
    bit_count: int
    frame_count: int
    valid_frames: int
    messages: list[str]
    packets: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    raw_path: str | None
    executable: str | None
    written_bytes: int
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _WaveSignal:
    samples: np.ndarray
    sample_rate: int
    channels: int
    sample_width: int
    frame_count: int


def inspect_ham_radio(
    input_path: Path,
    *,
    mode: HamMode = "afsk1200",
    reverse_audio: bool = False,
    invert_audio: bool = False,
    max_seconds: float | None = None,
) -> HamRadioResult:
    result = decode_ham_radio(
        input_path,
        None,
        mode=mode,
        backend="native",
        reverse_audio=reverse_audio,
        invert_audio=invert_audio,
        max_seconds=max_seconds,
    )
    return _replace_operation(result, "audio.ham.inspect")


def decode_ham_radio(
    input_path: Path,
    output_path: Path | None,
    *,
    mode: HamMode = "afsk1200",
    backend: HamBackend = "native",
    reverse_audio: bool = False,
    invert_audio: bool = False,
    max_seconds: float | None = None,
    raw_output: Path | None = None,
    multimon: Path | None = None,
) -> HamRadioResult:
    if mode != "afsk1200":
        raise ValueError("当前 ham 原生路径支持 afsk1200")
    if backend not in {"native", "multimon", "auto"}:
        raise ValueError("backend 必须是 native、multimon 或 auto")
    _ = multimon
    signal = _read_wav_signal(input_path, reverse_audio=reverse_audio, invert_audio=invert_audio)
    if max_seconds is not None:
        keep = max(1, int(max_seconds * signal.sample_rate))
        signal = _WaveSignal(
            signal.samples[:keep],
            signal.sample_rate,
            signal.channels,
            signal.sample_width,
            min(signal.frame_count, keep),
        )
    if raw_output is not None:
        _write_raw_s16(signal, raw_output, target_rate=22_050)
    decoded = _decode_afsk1200_native(signal.samples, signal.sample_rate)
    text = "\n".join(decoded["messages"])
    written = _write_text_output(output_path, text)
    return HamRadioResult(
        operation="audio.ham.decode",
        input_path=str(input_path),
        output_path=str(output_path) if output_path is not None else "-",
        output_paths=[str(output_path)] if output_path is not None else [],
        mode="afsk1200",
        backend="native",
        sample_rate=signal.sample_rate,
        channels=signal.channels,
        sample_width=signal.sample_width,
        samples=len(signal.samples),
        duration_seconds=len(signal.samples) / signal.sample_rate,
        demod_sample_rate=_NATIVE_RATE,
        bit_rate=_BIT_RATE,
        bit_count=decoded["bit_count"],
        frame_count=decoded["frame_count"],
        valid_frames=decoded["valid_frames"],
        messages=decoded["messages"],
        packets=decoded["packets"],
        findings=_find_aprs_hints(decoded["messages"]),
        raw_path=str(raw_output) if raw_output is not None else None,
        executable=None,
        written_bytes=written,
    )


def encode_ax25_afsk1200_wav(
    output_path: Path,
    *,
    source: str = "N0CALL",
    destination: str = "APRS",
    info: str = "flag{ham_radio}",
    path: list[str] | None = None,
    sample_rate: int = _NATIVE_RATE,
    amplitude: float = 0.65,
    preamble_flags: int = 24,
    trailer_flags: int = 8,
) -> HamRadioResult:
    frame = _build_ax25_ui_frame(source=source, destination=destination, path=path or [], info=info)
    bits = _hdlc_bits_for_frame(frame, preamble_flags=preamble_flags, trailer_flags=trailer_flags)
    samples = _synthesize_afsk_bits(bits, sample_rate=sample_rate, amplitude=amplitude)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pcm = np.clip(samples * 32767.0, -32768, 32767).astype("<i2")
    with wave.open(str(output_path), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(pcm.tobytes())
    message = f"{source}>{destination}{',' + ','.join(path) if path else ''}:{info}"
    return HamRadioResult(
        operation="audio.ham.encode",
        input_path="-",
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="afsk1200",
        backend="native",
        sample_rate=sample_rate,
        channels=1,
        sample_width=2,
        samples=len(samples),
        duration_seconds=len(samples) / sample_rate,
        demod_sample_rate=sample_rate,
        bit_rate=_BIT_RATE,
        bit_count=len(bits),
        frame_count=1,
        valid_frames=1,
        messages=[message],
        packets=[],
        findings=_find_aprs_hints([message]),
        raw_path=None,
        executable=None,
        written_bytes=output_path.stat().st_size,
    )


def _read_wav_signal(path: Path, *, reverse_audio: bool, invert_audio: bool) -> _WaveSignal:
    with wave.open(str(path), "rb") as wav:
        channels = wav.getnchannels()
        sample_width = wav.getsampwidth()
        sample_rate = wav.getframerate()
        frames = wav.getnframes()
        raw = wav.readframes(frames)
    data = _pcm_to_float(raw, sample_width)
    if channels > 1:
        data = data.reshape(-1, channels).mean(axis=1)
    if reverse_audio:
        data = data[::-1]
    if invert_audio:
        data = -data
    data = np.asarray(data, dtype=np.float64)
    data -= float(np.mean(data)) if len(data) else 0.0
    peak = float(np.max(np.abs(data))) if len(data) else 0.0
    if peak > 0:
        data /= peak
    return _WaveSignal(data, sample_rate, channels, sample_width, frames)


def _pcm_to_float(raw: bytes, sample_width: int) -> np.ndarray:
    if sample_width == 1:
        return (np.frombuffer(raw, dtype=np.uint8).astype(np.float64) - 128.0) / 128.0
    if sample_width == 2:
        return np.frombuffer(raw, dtype="<i2").astype(np.float64) / 32768.0
    if sample_width == 3:
        triples = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        vals = (
            triples[:, 0].astype(np.int32)
            | (triples[:, 1].astype(np.int32) << 8)
            | (triples[:, 2].astype(np.int32) << 16)
        )
        vals = np.where(vals & 0x800000, vals - 0x1000000, vals)
        return vals.astype(np.float64) / 8388608.0
    if sample_width == 4:
        return np.frombuffer(raw, dtype="<i4").astype(np.float64) / 2147483648.0
    raise ValueError(f"不支持的 WAV sample width：{sample_width}")


def _decode_afsk1200_native(samples: np.ndarray, sample_rate: int) -> dict[str, Any]:
    demod = _resample(samples, sample_rate, _NATIVE_RATE)
    if len(demod) < _NATIVE_RATE // _BIT_RATE * 16:
        return {"bit_count": 0, "frame_count": 0, "valid_frames": 0, "messages": [], "packets": []}
    sps = _NATIVE_RATE // _BIT_RATE
    best: dict[str, Any] | None = None
    for offset in range(sps):
        states = _tone_states(demod, offset=offset, samples_per_symbol=sps, sample_rate=_NATIVE_RATE)
        if len(states) < 16:
            continue
        for initial_previous in (states[0], 1 - states[0]):
            bits = _nrzi_decode(states, initial_previous=initial_previous)
            packets = _extract_ax25_packets(bits)
            candidate = {
                "bit_count": len(bits),
                "frame_count": len(packets["all_frames"]),
                "valid_frames": len(packets["valid_packets"]),
                "messages": [packet["message"] for packet in packets["valid_packets"]],
                "packets": packets["valid_packets"],
            }
            if best is None or _candidate_score(candidate) > _candidate_score(best):
                best = candidate
    return best or {"bit_count": 0, "frame_count": 0, "valid_frames": 0, "messages": [], "packets": []}


def _candidate_score(candidate: dict[str, Any]) -> tuple[int, int, int]:
    return (candidate["valid_frames"], len(candidate["messages"]), candidate["frame_count"])


def _resample(samples: np.ndarray, source_rate: int, target_rate: int) -> np.ndarray:
    if source_rate == target_rate:
        return np.asarray(samples, dtype=np.float64)
    if len(samples) == 0:
        return np.asarray([], dtype=np.float64)
    duration = len(samples) / source_rate
    target_len = max(1, round(duration * target_rate))
    source_x = np.linspace(0.0, duration, num=len(samples), endpoint=False)
    target_x = np.linspace(0.0, duration, num=target_len, endpoint=False)
    return np.interp(target_x, source_x, samples).astype(np.float64)


def _tone_states(
    samples: np.ndarray,
    *,
    offset: int,
    samples_per_symbol: int,
    sample_rate: int,
) -> np.ndarray:
    usable = len(samples) - offset
    count = usable // samples_per_symbol
    if count <= 0:
        return np.asarray([], dtype=np.uint8)
    windows = samples[offset : offset + count * samples_per_symbol].reshape(count, samples_per_symbol)
    window = np.hamming(samples_per_symbol)
    t = np.arange(samples_per_symbol, dtype=np.float64) / sample_rate
    mark_cos = np.cos(2.0 * np.pi * _MARK_FREQ * t)
    mark_sin = np.sin(2.0 * np.pi * _MARK_FREQ * t)
    space_cos = np.cos(2.0 * np.pi * _SPACE_FREQ * t)
    space_sin = np.sin(2.0 * np.pi * _SPACE_FREQ * t)
    weighted = windows * window
    mark_power = np.square(weighted @ mark_cos) + np.square(weighted @ mark_sin)
    space_power = np.square(weighted @ space_cos) + np.square(weighted @ space_sin)
    return (mark_power >= space_power).astype(np.uint8)


def _nrzi_decode(states: np.ndarray, *, initial_previous: int) -> list[int]:
    previous = int(initial_previous)
    bits: list[int] = []
    for state in states:
        current = int(state)
        bits.append(1 if current == previous else 0)
        previous = current
    return bits


def _extract_ax25_packets(bits: list[int]) -> dict[str, Any]:
    flag_indexes = _find_flags(bits)
    all_frames: list[bytes] = []
    valid_packets: list[dict[str, Any]] = []
    for left, right in pairwise(flag_indexes):
        if right <= left + 8:
            continue
        segment = bits[left + 8 : right]
        unstuffed = _unstuff_hdlc_bits(segment)
        if len(unstuffed) < 16 or len(unstuffed) % 8:
            continue
        frame = _bits_to_bytes_lsb(unstuffed)
        all_frames.append(frame)
        if len(frame) < 18 or not _valid_fcs(frame):
            continue
        packet = _parse_ax25_frame(frame[:-2])
        if packet is not None:
            valid_packets.append(packet)
    return {"all_frames": all_frames, "valid_packets": valid_packets}


def _find_flags(bits: list[int]) -> list[int]:
    indexes: list[int] = []
    flag = list(_FLAG_BITS)
    limit = len(bits) - len(flag) + 1
    for index in range(max(0, limit)):
        if bits[index : index + 8] == flag:
            indexes.append(index)
    return indexes


def _unstuff_hdlc_bits(bits: list[int]) -> list[int]:
    out: list[int] = []
    ones = 0
    index = 0
    while index < len(bits):
        bit = bits[index]
        out.append(bit)
        if bit:
            ones += 1
            if ones == 5:
                if index + 1 < len(bits) and bits[index + 1] == 0:
                    index += 1
                ones = 0
        else:
            ones = 0
        index += 1
    return out


def _bits_to_bytes_lsb(bits: list[int]) -> bytes:
    out = bytearray()
    for index in range(0, len(bits), 8):
        value = 0
        for shift, bit in enumerate(bits[index : index + 8]):
            value |= (bit & 1) << shift
        out.append(value)
    return bytes(out)


def _valid_fcs(frame_with_fcs: bytes) -> bool:
    if len(frame_with_fcs) < 2:
        return False
    expected = int.from_bytes(frame_with_fcs[-2:], "little")
    return _crc16_x25(frame_with_fcs[:-2]) == expected


def _crc16_x25(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
            crc &= 0xFFFF
    return (~crc) & 0xFFFF


def _parse_ax25_frame(frame: bytes) -> dict[str, Any] | None:
    offset = 0
    addresses: list[str] = []
    while offset + 7 <= len(frame):
        chunk = frame[offset : offset + 7]
        addresses.append(_decode_ax25_address(chunk))
        offset += 7
        if chunk[6] & 1:
            break
        if len(addresses) > 10:
            return None
    if len(addresses) < 2 or offset + 2 > len(frame):
        return None
    control = frame[offset]
    pid = frame[offset + 1]
    info_bytes = frame[offset + 2 :]
    info = info_bytes.decode("utf-8", "replace")
    destination, source, *digipeaters = addresses
    path = ",".join(digipeaters)
    via = f",{path}" if path else ""
    message = f"{source}>{destination}{via}:{info}"
    return {
        "source": source,
        "destination": destination,
        "path": digipeaters,
        "control": control,
        "pid": pid,
        "ui": control == _APRS_CONTROL and pid == _APRS_PID,
        "info": info,
        "info_hex": info_bytes.hex(),
        "message": message,
    }


def _decode_ax25_address(chunk: bytes) -> str:
    callsign = "".join(chr((value >> 1) & 0x7F) for value in chunk[:6]).strip()
    ssid = (chunk[6] >> 1) & 0x0F
    return f"{callsign}-{ssid}" if ssid else callsign


def _build_ax25_ui_frame(
    *,
    source: str,
    destination: str,
    path: list[str],
    info: str,
) -> bytes:
    addresses = [_encode_ax25_address(destination, last=False)]
    rest = [_encode_ax25_address(source, last=not path)]
    for index, item in enumerate(path):
        rest.append(_encode_ax25_address(item, last=index == len(path) - 1))
    body = b"".join(addresses + rest) + bytes([_APRS_CONTROL, _APRS_PID]) + info.encode("utf-8")
    fcs = _crc16_x25(body).to_bytes(2, "little")
    return body + fcs


def _encode_ax25_address(value: str, *, last: bool) -> bytes:
    if "-" in value:
        call, ssid_text = value.rsplit("-", 1)
        ssid = int(ssid_text or "0") & 0x0F
    else:
        call = value
        ssid = 0
    call = call.upper()[:6].ljust(6)
    encoded = bytearray((ord(char) << 1) & 0xFE for char in call)
    encoded.append(0x60 | (ssid << 1) | (1 if last else 0))
    return bytes(encoded)


def _hdlc_bits_for_frame(frame: bytes, *, preamble_flags: int, trailer_flags: int) -> list[int]:
    data_bits = _bytes_to_bits_lsb(frame)
    stuffed = _stuff_hdlc_bits(data_bits)
    return list(_FLAG_BITS) * preamble_flags + stuffed + list(_FLAG_BITS) * trailer_flags


def _bytes_to_bits_lsb(data: bytes) -> list[int]:
    return [(value >> shift) & 1 for value in data for shift in range(8)]


def _stuff_hdlc_bits(bits: list[int]) -> list[int]:
    out: list[int] = []
    ones = 0
    for bit in bits:
        out.append(bit)
        if bit:
            ones += 1
            if ones == 5:
                out.append(0)
                ones = 0
        else:
            ones = 0
    return out


def _synthesize_afsk_bits(bits: list[int], *, sample_rate: int, amplitude: float) -> np.ndarray:
    samples_per_symbol = sample_rate / _BIT_RATE
    state = 1
    phase = 0.0
    out: list[np.ndarray] = []
    cursor = 0.0
    for bit in bits:
        if bit == 0:
            state ^= 1
        start = round(cursor)
        cursor += samples_per_symbol
        stop = round(cursor)
        count = max(1, stop - start)
        freq = _MARK_FREQ if state else _SPACE_FREQ
        step = 2.0 * np.pi * freq / sample_rate
        indexes = np.arange(count, dtype=np.float64)
        chunk = amplitude * np.sin(phase + step * indexes)
        phase = (phase + step * count) % (2.0 * np.pi)
        out.append(chunk)
    return np.concatenate(out) if out else np.asarray([], dtype=np.float64)


def _write_raw_s16(signal: _WaveSignal, raw_path: Path, *, target_rate: int) -> None:
    resampled = _resample(signal.samples, signal.sample_rate, target_rate)
    pcm = np.clip(resampled * 32767.0, -32768, 32767).astype("<i2")
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(pcm.tobytes())


def _write_text_output(output_path: Path | None, text: str) -> int:
    if output_path is None:
        return 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = (text + ("\n" if text else "")).encode("utf-8")
    output_path.write_bytes(data)
    return len(data)


def _find_aprs_hints(messages: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        lower = message.lower()
        if "flag{" in lower:
            findings.append({"kind": "flag", "index": index, "text": message})
        if ">" in message and ":" in message:
            findings.append({"kind": "aprs", "index": index, "text": message})
        if any(token in lower for token in ("lat", "lon", "gps", "cq")):
            findings.append({"kind": "keyword", "index": index, "text": message})
    return findings[:20]


def _replace_operation(result: HamRadioResult, operation: str) -> HamRadioResult:
    values = asdict(result)
    values["operation"] = operation
    return HamRadioResult(**values)
