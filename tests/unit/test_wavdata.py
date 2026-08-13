from __future__ import annotations

import contextlib
import io
import json
import math
import tempfile
import unittest
import wave
from pathlib import Path

import numpy as np
from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.wavdata import (
    compare_wavdata,
    extract_channel_diff,
    extract_wav_lsb,
    fft_map_wavdata,
    freq_chars_wavdata,
    info_wavdata,
    wavdata_to_image,
)


def _bits_for_text(text: str) -> list[int]:
    bits: list[int] = []
    for value in text.encode("utf-8"):
        bits.extend((value >> shift) & 1 for shift in range(7, -1, -1))
    return bits


class WavDataTest(unittest.TestCase):
    def test_info_and_lsb_extract_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav = root / "lsb.wav"
            output = root / "flag.txt"
            bits = _bits_for_text("flag{wav_lsb}")
            samples = np.arange(len(bits), dtype=np.int16) << 1
            samples |= np.asarray(bits, dtype=np.int16)
            _write_wav(wav, samples.reshape(-1, 1), rate=8000)

            info = info_wavdata(wav)
            result = extract_wav_lsb(wav, output, channel="left", output_format="bytes")

            self.assertEqual(info.channels, 1)
            self.assertEqual(info.bits_per_sample, 16)
            self.assertEqual(output.read_bytes(), b"flag{wav_lsb}")
            self.assertEqual(result.findings[0]["kind"], "flag")

    def test_channel_diff_extract_bits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav = root / "diff.wav"
            output = root / "bits.txt"
            bits = "01001101"
            frames = []
            for bit in bits:
                right = 100
                diff = 2 if bit == "1" else 1
                frames.append((right + diff, right))
            _write_wav(wav, np.asarray(frames, dtype=np.int16), rate=8000)

            result = extract_channel_diff(
                wav,
                output,
                mapping={"1": "0", "2": "1"},
                output_format="bits",
            )

            self.assertEqual(output.read_text(encoding="ascii"), bits)
            self.assertEqual(result.bit_count, 8)

    def test_fft_map_and_freq_chars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fft_wav = root / "fft.wav"
            fft_out = root / "fft.txt"
            char_wav = root / "chars.wav"
            char_out = root / "chars.txt"
            freqs = [800.0, 900.0, 1000.0]
            # group-size 2: [0,1] -> alphabet[1] == 'A'; [0,2] -> alphabet[2] == 'B'
            _write_tones(fft_wav, [800.0, 900.0, 800.0, 1000.0], chunk_ms=100, rate=8000)
            fft_result = fft_map_wavdata(
                fft_wav,
                fft_out,
                freqs=freqs,
                alphabet="?AB",
                group_size=2,
                chunk_ms=100,
            )

            _write_tones(char_wav, [440.0, 440.0, 466.0], chunk_ms=100, rate=8000)
            char_result = freq_chars_wavdata(char_wav, char_out, chunk_ms=100, dedupe=True, freq_map={"a": 440.0, "b": 466.0})

            self.assertEqual(fft_out.read_text(encoding="utf-8"), "AB")
            self.assertEqual(fft_result.decoded_text, "AB")
            self.assertEqual(char_out.read_text(encoding="utf-8"), "ab")
            self.assertEqual(char_result.decoded_text, "ab")

    def test_compare_and_to_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "secret.wav"
            second = root / "cover.wav"
            compare_out = root / "compare.bin"
            image_wav = root / "image.wav"
            image_out = root / "flag.png"
            # Byte 'A' = 01000001, encoded as diff 1->0 and 2->1.
            bit_text = "01000001"
            cover = np.full((len(bit_text), 1), 1000, dtype=np.int16)
            secret = cover.copy()
            for index, bit in enumerate(bit_text):
                secret[index, 0] += 2 if bit == "1" else 1
            _write_wav(first, secret, rate=8000)
            _write_wav(second, cover, rate=8000)

            compare_result = compare_wavdata(
                first,
                second,
                compare_out,
                scale=32768,
                mapping={"1": "0", "2": "1"},
            )

            pixels = np.asarray([[0x1234, 0x5678], [0x90AB, 0xCDEF]], dtype=np.uint16).view(np.int16)
            _write_wav(image_wav, pixels, rate=8000)
            image_result = wavdata_to_image(image_wav, image_out, width=2, height=1, mode="rgba16stereo")
            img = Image.open(image_out)

            self.assertEqual(compare_out.read_bytes(), b"A")
            self.assertEqual(compare_result.bit_count, 8)
            self.assertEqual(img.getpixel((0, 0)), (0x12, 0x34, 0x56, 0x78))
            self.assertEqual(img.getpixel((1, 0)), (0x90, 0xAB, 0xCD, 0xEF))
            self.assertEqual(image_result.width, 2)

    def test_cli_wavdata_lsb_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav = root / "lsb.wav"
            output = root / "out.txt"
            bits = _bits_for_text("hi")
            samples = (np.arange(len(bits), dtype=np.int16) << 1) | np.asarray(bits, dtype=np.int16)
            _write_wav(wav, samples.reshape(-1, 1), rate=8000)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "audio",
                        "wavdata",
                        "lsb",
                        str(wav),
                        "-o",
                        str(output),
                        "--channel",
                        "left",
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "audio.wavdata.lsb")
            self.assertEqual(output.read_bytes(), b"hi")


def _write_wav(path: Path, data: np.ndarray, *, rate: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if data.ndim == 1:
        data = data.reshape(-1, 1)
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(data.shape[1])
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(data.astype("<i2").tobytes())


def _write_tones(path: Path, freqs: list[float], *, chunk_ms: float, rate: int) -> None:
    samples: list[np.ndarray] = []
    chunk_size = round(rate * chunk_ms / 1000.0)
    t = np.arange(chunk_size, dtype=np.float64) / rate
    for freq in freqs:
        samples.append(0.8 * np.sin(2.0 * math.pi * freq * t))
    data = np.concatenate(samples)
    pcm = np.clip(data * 32767.0, -32768, 32767).astype("<i2")
    _write_wav(path, pcm.reshape(-1, 1), rate=rate)


if __name__ == "__main__":
    unittest.main()
