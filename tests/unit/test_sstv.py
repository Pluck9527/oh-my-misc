from __future__ import annotations

import json
import wave
from pathlib import Path

import numpy as np
from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.sstv import MARTIN_1, decode_sstv, inspect_sstv


def _tone(freq: float, duration: float, sample_rate: int = 8000) -> np.ndarray:
    count = max(1, round(duration * sample_rate))
    t = np.arange(count, dtype=np.float32) / sample_rate
    return (0.65 * np.sin(2 * np.pi * freq * t)).astype(np.float32)


def _write_wav(path: Path, samples: np.ndarray, sample_rate: int = 8000) -> None:
    pcm = np.clip(samples, -1.0, 1.0)
    ints = (pcm * 32767).astype("<i2")
    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(ints.tobytes())


def _vis_header(code: int, sample_rate: int = 8000) -> np.ndarray:
    data_bits = [(code >> bit) & 1 for bit in range(7)]
    parity_bit = sum(data_bits) % 2
    chunks = [
        _tone(1900, 0.300, sample_rate),
        _tone(1200, 0.010, sample_rate),
        _tone(1900, 0.300, sample_rate),
        _tone(1200, 0.030, sample_rate),
    ]
    chunks.extend(_tone(1100 if bit else 1300, 0.030, sample_rate) for bit in data_bits)
    chunks.append(_tone(1100 if parity_bit else 1300, 0.030, sample_rate))
    chunks.append(_tone(1200, 0.030, sample_rate))
    return np.concatenate(chunks)


def _martin1_lines(lines: int, sample_rate: int = 8000) -> np.ndarray:
    chunks: list[np.ndarray] = []
    for _ in range(lines):
        chunks.extend(
            [
                _tone(1200, MARTIN_1.sync_pulse, sample_rate),
                _tone(1500, MARTIN_1.sync_porch, sample_rate),
                _tone(1500, MARTIN_1.scan_time, sample_rate),
                _tone(1500, MARTIN_1.sep_pulse, sample_rate),
                _tone(1500, MARTIN_1.scan_time, sample_rate),
                _tone(1500, MARTIN_1.sep_pulse, sample_rate),
                _tone(2300, MARTIN_1.scan_time, sample_rate),
                _tone(1500, MARTIN_1.sep_pulse, sample_rate),
            ]
        )
    chunks.append(np.zeros(round(0.050 * sample_rate), dtype=np.float32))
    return np.concatenate(chunks)


def _martin1_wav(path: Path, *, lines: int = 2, sample_rate: int = 8000) -> None:
    samples = np.concatenate([_vis_header(44, sample_rate), _martin1_lines(lines, sample_rate)])
    _write_wav(path, samples, sample_rate)


def test_sstv_inspect_detects_martin1_vis(tmp_path: Path) -> None:
    wav_path = tmp_path / "m1.wav"
    _write_wav(wav_path, np.concatenate([_vis_header(44), np.zeros(400, dtype=np.float32)]))

    result = inspect_sstv(wav_path)

    assert result.operation == "audio.sstv.inspect"
    assert result.mode == "Martin 1"
    assert result.vis_code == 44
    assert result.sample_rate == 8000
    assert result.width == 320
    assert result.height == 256


def test_sstv_decode_partial_martin1_to_png(tmp_path: Path) -> None:
    wav_path = tmp_path / "m1.wav"
    output = tmp_path / "decoded.png"
    _martin1_wav(wav_path, lines=2)

    result = decode_sstv(wav_path, output, max_lines=2)

    assert result.operation == "audio.sstv.decode"
    assert result.mode == "Martin 1"
    assert result.decoded_lines == 2
    assert result.width == 320
    assert result.height == 2
    assert result.written_bytes == output.stat().st_size
    with Image.open(output) as image:
        assert image.size == (320, 2)
        red, green, blue = image.convert("RGB").resize((1, 1)).getpixel((0, 0))
    assert red > 220
    assert green < 40
    assert blue < 40


def test_sstv_cli_inspect_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    wav_path = tmp_path / "m1.wav"
    _write_wav(wav_path, np.concatenate([_vis_header(44), np.zeros(400, dtype=np.float32)]))

    assert main(["audio", "sstv", "inspect", str(wav_path), "--json"]) == 0

    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "audio.sstv.inspect"
    assert data["mode"] == "Martin 1"
    assert data["vis_code"] == 44


def test_sstv_cli_decode_forced_mode(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    wav_path = tmp_path / "m1.wav"
    output = tmp_path / "decoded.png"
    _martin1_wav(wav_path, lines=1)

    assert (
        main(
            [
                "audio",
                "sstv",
                "decode",
                str(wav_path),
                "--mode",
                "m1",
                "--max-lines",
                "1",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )

    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "audio.sstv.decode"
    assert data["output_path"] == str(output)
    assert output.exists()
