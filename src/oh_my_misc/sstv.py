from __future__ import annotations

import wave
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageOps

VIS_BIT_SIZE = 0.030
BREAK_OFFSET = 0.300
LEADER_OFFSET = 0.010 + BREAK_OFFSET
VIS_START_OFFSET = 0.300 + LEADER_OFFSET
HDR_SIZE = 0.030 + VIS_START_OFFSET
HDR_WINDOW_SIZE = 0.010

SSTV_MIN_FREQ = 1500.0
SSTV_MAX_FREQ = 2300.0
SSTV_FREQ_STEP = (SSTV_MAX_FREQ - SSTV_MIN_FREQ) / 255.0


@dataclass(frozen=True)
class SSTVModeSpec:
    code: int
    name: str
    color: str
    line_width: int
    line_count: int
    scan_time: float
    sync_pulse: float
    sync_porch: float
    sep_pulse: float
    chan_count: int
    chan_sync: int
    chan_offsets: tuple[float, ...]
    line_time: float
    pixel_time: float
    window_factor: float
    has_start_sync: bool
    has_half_scan: bool
    has_alt_scan: bool
    half_scan_time: float = 0.0
    half_pixel_time: float = 0.0


@dataclass(frozen=True)
class SSTVResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    vis_code: int | None
    sample_rate: int
    samples: int
    channels: int
    duration_seconds: float
    width: int
    height: int
    decoded_lines: int
    reverse_audio: bool
    invert_image: bool
    written_bytes: int
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


def _gbr_mode(
    code: int,
    name: str,
    *,
    scan_time: float,
    sync_pulse: float,
    sync_porch: float,
    sep_pulse: float,
    chan_offsets: tuple[float, float, float],
    line_time: float,
    window_factor: float,
    has_start_sync: bool,
    chan_sync: int,
) -> SSTVModeSpec:
    return SSTVModeSpec(
        code=code,
        name=name,
        color="GBR",
        line_width=320,
        line_count=256,
        scan_time=scan_time,
        sync_pulse=sync_pulse,
        sync_porch=sync_porch,
        sep_pulse=sep_pulse,
        chan_count=3,
        chan_sync=chan_sync,
        chan_offsets=chan_offsets,
        line_time=line_time,
        pixel_time=scan_time / 320,
        window_factor=window_factor,
        has_start_sync=has_start_sync,
        has_half_scan=False,
        has_alt_scan=False,
    )


def _martin_mode(code: int, name: str, scan_time: float, window_factor: float) -> SSTVModeSpec:
    sync_pulse = 0.004862
    sync_porch = 0.000572
    sep_pulse = 0.000572
    chan_time = sep_pulse + scan_time
    first = sync_pulse + sync_porch
    offsets = (first, first + chan_time, first + 2 * chan_time)
    line_time = sync_pulse + sync_porch + 3 * chan_time
    return _gbr_mode(
        code,
        name,
        scan_time=scan_time,
        sync_pulse=sync_pulse,
        sync_porch=sync_porch,
        sep_pulse=sep_pulse,
        chan_offsets=offsets,
        line_time=line_time,
        window_factor=window_factor,
        has_start_sync=False,
        chan_sync=0,
    )


def _scottie_mode(code: int, name: str, scan_time: float, window_factor: float) -> SSTVModeSpec:
    sync_pulse = 0.009000
    sync_porch = 0.001500
    sep_pulse = 0.001500
    chan_time = sep_pulse + scan_time
    first = sync_pulse + sync_porch + chan_time
    offsets = (first, first + chan_time, sync_pulse + sync_porch)
    line_time = sync_pulse + 3 * chan_time
    return _gbr_mode(
        code,
        name,
        scan_time=scan_time,
        sync_pulse=sync_pulse,
        sync_porch=sync_porch,
        sep_pulse=sep_pulse,
        chan_offsets=offsets,
        line_time=line_time,
        window_factor=window_factor,
        has_start_sync=True,
        chan_sync=2,
    )


def _robot36_mode() -> SSTVModeSpec:
    scan_time = 0.088000
    half_scan_time = 0.044000
    sync_pulse = 0.009000
    sync_porch = 0.003000
    sep_pulse = 0.004500
    sep_porch = 0.001500
    chan_time = sep_pulse + scan_time
    first = sync_pulse + sync_porch
    second = first + chan_time + sep_porch
    return SSTVModeSpec(
        code=8,
        name="Robot 36",
        color="YUV",
        line_width=320,
        line_count=240,
        scan_time=scan_time,
        sync_pulse=sync_pulse,
        sync_porch=sync_porch,
        sep_pulse=sep_pulse,
        chan_count=2,
        chan_sync=0,
        chan_offsets=(first, second),
        line_time=second + half_scan_time,
        pixel_time=scan_time / 320,
        half_pixel_time=half_scan_time / 320,
        window_factor=7.70,
        has_start_sync=False,
        has_half_scan=True,
        has_alt_scan=True,
        half_scan_time=half_scan_time,
    )


def _robot72_mode() -> SSTVModeSpec:
    scan_time = 0.138000
    half_scan_time = 0.069000
    sync_pulse = 0.009000
    sync_porch = 0.003000
    sep_pulse = 0.004500
    sep_porch = 0.001500
    chan_time = sep_pulse + scan_time
    half_chan_time = sep_pulse + half_scan_time
    first = sync_pulse + sync_porch
    second = first + chan_time + sep_porch
    third = second + half_chan_time + sep_porch
    return SSTVModeSpec(
        code=12,
        name="Robot 72",
        color="YUV",
        line_width=320,
        line_count=240,
        scan_time=scan_time,
        sync_pulse=sync_pulse,
        sync_porch=sync_porch,
        sep_pulse=sep_pulse,
        chan_count=3,
        chan_sync=0,
        chan_offsets=(first, second, third),
        line_time=third + half_scan_time,
        pixel_time=scan_time / 320,
        half_pixel_time=half_scan_time / 320,
        window_factor=4.88,
        has_start_sync=False,
        has_half_scan=True,
        has_alt_scan=False,
        half_scan_time=half_scan_time,
    )


MARTIN_1 = _martin_mode(44, "Martin 1", 0.146432, 2.34)
MARTIN_2 = _martin_mode(40, "Martin 2", 0.073216, 4.68)
SCOTTIE_1 = _scottie_mode(60, "Scottie 1", 0.138240, 2.48)
SCOTTIE_2 = _scottie_mode(56, "Scottie 2", 0.088064, 3.82)
SCOTTIE_DX = _scottie_mode(76, "Scottie DX", 0.345600, 0.98)
ROBOT_36 = _robot36_mode()
ROBOT_72 = _robot72_mode()

VIS_MAP: dict[int, SSTVModeSpec] = {
    8: ROBOT_36,
    12: ROBOT_72,
    40: MARTIN_2,
    44: MARTIN_1,
    56: SCOTTIE_2,
    60: SCOTTIE_1,
    76: SCOTTIE_DX,
}

MODE_BY_NAME: dict[str, SSTVModeSpec] = {
    "m1": MARTIN_1,
    "martin1": MARTIN_1,
    "martin-1": MARTIN_1,
    "martin_1": MARTIN_1,
    "martin 1": MARTIN_1,
    "m2": MARTIN_2,
    "martin2": MARTIN_2,
    "martin-2": MARTIN_2,
    "martin_2": MARTIN_2,
    "martin 2": MARTIN_2,
    "s1": SCOTTIE_1,
    "scottie1": SCOTTIE_1,
    "scottie-1": SCOTTIE_1,
    "scottie_1": SCOTTIE_1,
    "scottie 1": SCOTTIE_1,
    "s2": SCOTTIE_2,
    "scottie2": SCOTTIE_2,
    "scottie-2": SCOTTIE_2,
    "scottie_2": SCOTTIE_2,
    "scottie 2": SCOTTIE_2,
    "sdx": SCOTTIE_DX,
    "scottiedx": SCOTTIE_DX,
    "scottie-dx": SCOTTIE_DX,
    "scottie_dx": SCOTTIE_DX,
    "scottie dx": SCOTTIE_DX,
    "r36": ROBOT_36,
    "robot36": ROBOT_36,
    "robot-36": ROBOT_36,
    "robot_36": ROBOT_36,
    "robot 36": ROBOT_36,
    "r72": ROBOT_72,
    "robot72": ROBOT_72,
    "robot-72": ROBOT_72,
    "robot_72": ROBOT_72,
    "robot 72": ROBOT_72,
}

MODE_CHOICES = tuple(sorted({"auto", *MODE_BY_NAME.keys()}))


def decode_sstv(
    input_path: Path,
    output_path: Path,
    *,
    mode: str = "auto",
    skip: float = 0.0,
    reverse_audio: bool = False,
    invert_image: bool = False,
    max_lines: int | None = None,
) -> SSTVResult:
    samples, sample_rate, channels, original_sample_count = _load_and_prepare(
        input_path, skip=skip, reverse_audio=reverse_audio
    )
    header_end = _find_header(samples, sample_rate)
    if header_end is None:
        raise ValueError("SSTV calibration header not found")

    vis_code: int | None
    try:
        vis_code = _decode_vis(samples, sample_rate, header_end)
    except ValueError:
        if _normalise_mode_name(mode) == "auto":
            raise
        vis_code = None

    spec = _resolve_mode(mode, vis_code)
    image_start = header_end + round(VIS_BIT_SIZE * 9 * sample_rate)
    image_data, decoded_lines = _decode_image_data(
        samples, sample_rate, spec, image_start, max_lines=max_lines
    )
    if decoded_lines <= 0:
        raise EOFError("Reached end of audio before SSTV image data")

    image = _draw_image(image_data, spec)
    if invert_image:
        image = ImageOps.invert(image.convert("RGB"))
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)
    written_bytes = output_path.stat().st_size

    return SSTVResult(
        operation="audio.sstv.decode",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode=spec.name,
        vis_code=vis_code,
        sample_rate=sample_rate,
        samples=original_sample_count,
        channels=channels,
        duration_seconds=original_sample_count / sample_rate,
        width=image.width,
        height=image.height,
        decoded_lines=decoded_lines,
        reverse_audio=reverse_audio,
        invert_image=invert_image,
        written_bytes=written_bytes,
    )


def inspect_sstv(
    input_path: Path,
    *,
    mode: str = "auto",
    skip: float = 0.0,
    reverse_audio: bool = False,
) -> SSTVResult:
    samples, sample_rate, channels, original_sample_count = _load_and_prepare(
        input_path, skip=skip, reverse_audio=reverse_audio
    )
    header_end = _find_header(samples, sample_rate)
    if header_end is None:
        raise ValueError("SSTV calibration header not found")

    vis_code: int | None
    try:
        vis_code = _decode_vis(samples, sample_rate, header_end)
    except ValueError:
        if _normalise_mode_name(mode) == "auto":
            raise
        vis_code = None
    spec = _resolve_mode(mode, vis_code)
    return SSTVResult(
        operation="audio.sstv.inspect",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        mode=spec.name,
        vis_code=vis_code,
        sample_rate=sample_rate,
        samples=original_sample_count,
        channels=channels,
        duration_seconds=original_sample_count / sample_rate,
        width=spec.line_width,
        height=spec.line_count,
        decoded_lines=0,
        reverse_audio=reverse_audio,
        invert_image=False,
        written_bytes=0,
    )


def load_wav_mono(path: Path) -> tuple[np.ndarray, int, int]:
    with wave.open(str(path), "rb") as wav_file:
        if wav_file.getcomptype() != "NONE":
            raise ValueError("compressed WAV files are not supported")
        channels = wav_file.getnchannels()
        sample_width = wav_file.getsampwidth()
        sample_rate = wav_file.getframerate()
        frame_count = wav_file.getnframes()
        payload = wav_file.readframes(frame_count)

    if channels <= 0:
        raise ValueError("WAV channel count is invalid")
    samples = _decode_pcm(payload, sample_width)
    usable = (samples.size // channels) * channels
    if usable == 0:
        raise ValueError("WAV file has no samples")
    samples = samples[:usable].reshape(-1, channels)
    mono = samples.mean(axis=1, dtype=np.float32)
    return mono.astype(np.float32, copy=False), sample_rate, channels


def calc_lum(freq: float) -> int:
    lum = round((freq - SSTV_MIN_FREQ) / SSTV_FREQ_STEP)
    return min(max(lum, 0), 255)


def _load_and_prepare(
    input_path: Path, *, skip: float, reverse_audio: bool
) -> tuple[np.ndarray, int, int, int]:
    if skip < 0:
        raise ValueError("--skip must be non-negative")
    samples, sample_rate, channels = load_wav_mono(input_path)
    original_sample_count = int(samples.size)
    if skip:
        start = round(skip * sample_rate)
        samples = samples[start:]
    if reverse_audio:
        samples = samples[::-1].copy()
    if samples.size == 0:
        raise ValueError("no audio samples left after --skip")
    return samples, sample_rate, channels, original_sample_count


def _decode_pcm(payload: bytes, sample_width: int) -> np.ndarray:
    if sample_width == 1:
        data = np.frombuffer(payload, dtype=np.uint8).astype(np.float32)
        return (data - 128.0) / 128.0
    if sample_width == 2:
        data = np.frombuffer(payload, dtype="<i2").astype(np.float32)
        return data / 32768.0
    if sample_width == 3:
        raw = np.frombuffer(payload, dtype=np.uint8)
        usable = (raw.size // 3) * 3
        triads = raw[:usable].reshape(-1, 3).astype(np.int32)
        values = triads[:, 0] | (triads[:, 1] << 8) | (triads[:, 2] << 16)
        sign = values & 0x800000 != 0
        values[sign] -= 1 << 24
        return values.astype(np.float32) / 8388608.0
    if sample_width == 4:
        data = np.frombuffer(payload, dtype="<i4").astype(np.float32)
        return data / 2147483648.0
    raise ValueError(f"unsupported WAV sample width: {sample_width} bytes")


def _normalise_mode_name(mode: str) -> str:
    return mode.strip().lower().replace("/", "-")


def _resolve_mode(mode: str, vis_code: int | None) -> SSTVModeSpec:
    key = _normalise_mode_name(mode)
    if key == "auto":
        if vis_code is None or vis_code not in VIS_MAP:
            raise ValueError("SSTV mode is unsupported or missing from VIS header")
        return VIS_MAP[vis_code]
    if key not in MODE_BY_NAME:
        valid = ", ".join(sorted({"auto", "m1", "m2", "s1", "s2", "sdx", "r36", "r72"}))
        raise ValueError(f"unsupported SSTV mode {mode!r}; expected one of: {valid}")
    return MODE_BY_NAME[key]


def _find_header(samples: np.ndarray, sample_rate: int) -> int | None:
    header_size = round(HDR_SIZE * sample_rate)
    window_size = max(8, round(HDR_WINDOW_SIZE * sample_rate))
    if samples.size < header_size + window_size:
        return None

    leader_1_sample = 0
    leader_1_search = leader_1_sample + window_size
    break_sample = round(BREAK_OFFSET * sample_rate)
    break_search = break_sample + window_size
    leader_2_sample = round(LEADER_OFFSET * sample_rate)
    leader_2_search = leader_2_sample + window_size
    vis_start_sample = round(VIS_START_OFFSET * sample_rate)
    vis_start_search = vis_start_sample + window_size
    jump_size = max(1, round(0.002 * sample_rate))

    max_start = samples.size - header_size
    for current_sample in range(0, max_start, jump_size):
        search_area = samples[current_sample : current_sample + header_size]
        leader_1_area = search_area[leader_1_sample:leader_1_search]
        break_area = search_area[break_sample:break_search]
        leader_2_area = search_area[leader_2_sample:leader_2_search]
        vis_start_area = search_area[vis_start_sample:vis_start_search]
        if (
            abs(_peak_fft_freq(leader_1_area, sample_rate) - 1900.0) < 50.0
            and abs(_peak_fft_freq(break_area, sample_rate) - 1200.0) < 50.0
            and abs(_peak_fft_freq(leader_2_area, sample_rate) - 1900.0) < 50.0
            and abs(_peak_fft_freq(vis_start_area, sample_rate) - 1200.0) < 50.0
        ):
            return current_sample + header_size
    return None


def _decode_vis(samples: np.ndarray, sample_rate: int, vis_start: int) -> int:
    bit_size = round(VIS_BIT_SIZE * sample_rate)
    if bit_size <= 0:
        raise ValueError("sample rate is too low for VIS decoding")
    vis_bits: list[int] = []
    for bit_idx in range(8):
        bit_offset = vis_start + bit_idx * bit_size
        section = samples[bit_offset : bit_offset + bit_size]
        if section.size < bit_size:
            raise ValueError("VIS header is truncated")
        freq = _peak_fft_freq(section, sample_rate)
        vis_bits.append(int(freq <= 1200.0))

    if sum(vis_bits) % 2 != 0:
        raise ValueError("Error decoding VIS header (invalid parity bit)")

    vis_value = 0
    for bit in vis_bits[-2::-1]:
        vis_value = (vis_value << 1) | bit
    if vis_value not in VIS_MAP:
        raise ValueError(f"SSTV mode is unsupported (VIS: {vis_value})")
    return vis_value


def _align_sync(
    samples: np.ndarray,
    sample_rate: int,
    mode: SSTVModeSpec,
    align_start: int,
    *,
    start_of_sync: bool = True,
) -> int | None:
    sync_window = max(8, round(mode.sync_pulse * 1.4 * sample_rate))
    align_start = max(0, align_start)
    align_stop = samples.size - sync_window
    if align_stop <= align_start:
        return None

    current_sample = align_start
    for current_sample in range(align_start, align_stop):
        section = samples[current_sample : current_sample + sync_window]
        if _peak_fft_freq(section, sample_rate) > 1350.0:
            break

    end_sync = current_sample + (sync_window // 2)
    if start_of_sync:
        sync_start = end_sync - round(mode.sync_pulse * sample_rate)
        return max(0, sync_start)
    return end_sync


def _decode_image_data(
    samples: np.ndarray,
    sample_rate: int,
    mode: SSTVModeSpec,
    image_start: int,
    *,
    max_lines: int | None,
) -> tuple[list[list[list[int]]], int]:
    height = mode.line_count if max_lines is None else min(mode.line_count, max(1, max_lines))
    channels = mode.chan_count
    width = mode.line_width
    image_data = [[[0 for _ in range(width)] for _ in range(channels)] for _ in range(height)]

    window_factor = mode.window_factor
    centre_window_time = (mode.pixel_time * window_factor) / 2.0
    pixel_window = max(8, round(centre_window_time * 2.0 * sample_rate))

    seq_start: int | None = image_start
    if mode.has_start_sync:
        seq_start = _align_sync(samples, sample_rate, mode, image_start, start_of_sync=False)
        if seq_start is None:
            return [], 0

    decoded_lines = 0
    for line in range(height):
        if seq_start is None:
            break
        if mode.chan_sync > 0 and line == 0:
            sync_offset = mode.chan_offsets[mode.chan_sync]
            seq_start -= round((sync_offset + mode.scan_time) * sample_rate)

        for chan in range(channels):
            if chan == mode.chan_sync:
                if line > 0 or chan > 0:
                    seq_start += round(mode.line_time * sample_rate)
                seq_start = _align_sync(samples, sample_rate, mode, seq_start)
                if seq_start is None:
                    return image_data[:decoded_lines], decoded_lines

            pixel_time = mode.pixel_time
            current_pixel_window = pixel_window
            current_centre_window_time = centre_window_time
            if mode.has_half_scan and chan > 0:
                pixel_time = mode.half_pixel_time
                current_centre_window_time = (pixel_time * window_factor) / 2.0
                current_pixel_window = max(8, round(current_centre_window_time * 2.0 * sample_rate))

            for px in range(width):
                chan_offset = mode.chan_offsets[chan]
                px_pos = round(
                    seq_start
                    + (chan_offset + px * pixel_time - current_centre_window_time) * sample_rate
                )
                px_pos = max(0, px_pos)
                px_end = px_pos + current_pixel_window
                if px_end > samples.size:
                    return image_data[:decoded_lines], decoded_lines
                pixel_area = samples[px_pos:px_end]
                freq = _peak_fft_freq(pixel_area, sample_rate)
                image_data[line][chan][px] = calc_lum(freq)
        decoded_lines = line + 1
    return image_data[:decoded_lines], decoded_lines


def _draw_image(image_data: list[list[list[int]]], mode: SSTVModeSpec) -> Image.Image:
    if not image_data:
        raise EOFError("no SSTV image lines decoded")
    col_mode = "YCbCr" if mode.color == "YUV" else "RGB"
    width = mode.line_width
    height = len(image_data)
    image = Image.new(col_mode, (width, height))
    pixel_data = image.load()

    for y in range(height):
        odd_line = y % 2
        for x in range(width):
            if mode.chan_count == 2 and mode.has_alt_scan:
                cb_line = y - (odd_line - 1)
                cr_line = y - odd_line
                cb_line = min(max(cb_line, 0), height - 1)
                cr_line = min(max(cr_line, 0), height - 1)
                pixel = (
                    image_data[y][0][x],
                    image_data[cb_line][1][x],
                    image_data[cr_line][1][x],
                )
            elif mode.chan_count == 3 and mode.color == "GBR":
                pixel = (image_data[y][2][x], image_data[y][0][x], image_data[y][1][x])
            elif mode.chan_count == 3 and mode.color == "YUV":
                pixel = (image_data[y][0][x], image_data[y][2][x], image_data[y][1][x])
            else:
                pixel = tuple(image_data[y][chan][x] for chan in range(mode.chan_count))
            pixel_data[x, y] = pixel

    if image.mode != "RGB":
        image = image.convert("RGB")
    return image


def _peak_fft_freq(data: np.ndarray, sample_rate: int) -> float:
    if data.size < 4:
        return 0.0
    data = np.asarray(data, dtype=np.float32)
    if not np.any(data):
        return 0.0
    windowed = data * np.hanning(data.size)
    fft = np.abs(np.fft.rfft(windowed))
    if fft.size == 0:
        return 0.0
    peak_idx = int(np.argmax(fft))
    peak = _barycentric_peak_interp(fft, peak_idx)
    return peak * sample_rate / data.size


def _barycentric_peak_interp(bins: np.ndarray, index: int) -> float:
    y1 = bins[index] if index <= 0 else bins[index - 1]
    y3 = bins[index] if index + 1 >= bins.size else bins[index + 1]
    denom = y3 + bins[index] + y1
    if denom == 0:
        return float(index)
    return float((y3 - y1) / denom + index)
