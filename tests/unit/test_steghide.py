from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import wave
from pathlib import Path

import numpy as np
from Crypto.Cipher import AES
from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.jphs import _read_jpeg_dct_image, _write_jpeg_dct_image
from oh_my_misc.steghide import (
    _bits_from_bytes,
    _bytes_from_bits,
    _mcrypt_md5_key,
    _SteghideSelector,
    brute_steghide,
    extract_steghide,
    extract_steghide_native,
)


class SteghideTest(unittest.TestCase):
    def test_extract_uses_empty_password_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "empty.wav"
            output = root / "payload.txt"
            _write_native_steghide_wav(stego, b"flag{empty_steghide}", password="")

            result = extract_steghide(
                stego, output, steghide_path=root / "ignored-steghide", backend="tool"
            )

            self.assertEqual(result.operation, "image.steghide.extract-native")
            self.assertEqual(result.tool_path, "python")
            self.assertEqual(result.found_password, "")
            self.assertEqual(output.read_bytes(), b"flag{empty_steghide}")

    def test_brute_wordlist_finds_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "secret.wav"
            words = root / "words.txt"
            output = root / "payload.txt"
            _write_native_steghide_wav(
                stego, b"flag{letmein}", password="letmein", encrypted=True
            )
            words.write_text("bad\nletmein\n", encoding="utf-8")

            result = brute_steghide(
                stego,
                words,
                output,
                steghide_path=root / "ignored-steghide",
                backend="tool",
                contains=b"flag{",
                include_empty=False,
            )

            self.assertEqual(result.operation, "image.steghide.brute-native")
            self.assertEqual(result.tool_path, "python")
            self.assertEqual(result.found_password, "letmein")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(output.read_bytes(), b"flag{letmein}")

    def test_cli_extract_wordlist_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "secret.wav"
            words = root / "words.txt"
            output = root / "payload.txt"
            _write_native_steghide_wav(
                stego, b"flag{hunter2}", password="hunter2", encrypted=True
            )
            words.write_text("wrong\nhunter2\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "steghide",
                        "extract",
                        str(stego),
                        "--wordlist",
                        str(words),
                        "--no-empty",
                        "--backend",
                        "tool",
                        "--contains",
                        "flag{",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.steghide.brute-native")
            self.assertEqual(payload["tool_path"], "python")
            self.assertEqual(payload["found_password"], "hunter2")
            self.assertEqual(payload["attempts"], 2)
            self.assertEqual(output.read_bytes(), b"flag{hunter2}")

    def test_native_wav_extracts_without_external_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "native.wav"
            output = root / "payload.txt"
            _write_native_steghide_wav(stego, b"flag{builtin_steghide}", password="")

            result = extract_steghide(stego, output, backend="native")

            self.assertEqual(result.operation, "image.steghide.extract-native")
            self.assertEqual(result.backend, "native")
            self.assertEqual(result.tool_path, "python")
            self.assertEqual(result.carrier_format, "wav")
            self.assertFalse(result.encrypted)
            self.assertEqual(output.read_bytes(), b"flag{builtin_steghide}")

    def test_native_bmp_extracts_without_external_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "native.bmp"
            _write_native_steghide_bmp(stego, b"flag{bmp_native}", password="")

            payload = extract_steghide_native(stego, password="")

            self.assertEqual(payload.data, b"flag{bmp_native}")
            self.assertEqual(payload.carrier_format, "bmp")

    def test_native_au_extracts_without_external_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "native.au"
            _write_native_steghide_au(stego, b"flag{au_native}", password="")

            payload = extract_steghide_native(stego, password="")

            self.assertEqual(payload.data, b"flag{au_native}")
            self.assertEqual(payload.carrier_format, "au")

    def test_native_jpeg_extracts_without_external_tool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "native.jpg"
            _write_native_steghide_jpeg(stego, b"flag{jpeg_native}", password="")

            payload = extract_steghide_native(stego, password="")

            self.assertEqual(payload.data, b"flag{jpeg_native}")
            self.assertEqual(payload.carrier_format, "jpeg")
            self.assertFalse(payload.encrypted)

    def test_native_wav_extracts_aes_cbc_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "encrypted.wav"
            _write_native_steghide_wav(
                stego, b"flag{aes_native}", password="s3cr3t", encrypted=True
            )

            payload = extract_steghide_native(stego, password="s3cr3t")

            self.assertEqual(payload.data, b"flag{aes_native}")
            self.assertTrue(payload.encrypted)
            self.assertEqual(payload.carrier_format, "wav")

    def test_cli_auto_uses_native_wav_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "native.wav"
            output = root / "payload.txt"
            _write_native_steghide_wav(stego, b"flag{cli_native}", password="")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "stego",
                        "steghide",
                        "extract",
                        str(stego),
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.steghide.extract-native")
            self.assertEqual(payload["backend"], "native")
            self.assertEqual(payload["tool_path"], "python")
            self.assertEqual(output.read_bytes(), b"flag{cli_native}")

    def test_native_brute_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stego = root / "native-brute.wav"
            words = root / "words.txt"
            output = root / "payload.txt"
            _write_native_steghide_wav(
                stego, b"flag{native_brute}", password="open-sesame", encrypted=True
            )
            words.write_text("bad\nopen-sesame\n", encoding="utf-8")

            result = brute_steghide(
                stego,
                words,
                output,
                backend="native",
                contains=b"flag{",
                include_empty=False,
            )

            self.assertEqual(result.operation, "image.steghide.brute-native")
            self.assertEqual(result.found_password, "open-sesame")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(output.read_bytes(), b"flag{native_brute}")

def _write_native_steghide_wav(
    path: Path, payload: bytes, *, password: str, encrypted: bool = False
) -> None:
    bits = _build_steghide_bits(payload, password=password, encrypted=encrypted)
    samples = [((index * 73) % 60000) - 30000 for index in range(max(4096, len(bits) * 4))]
    selector = _SteghideSelector(len(samples), password)
    sample_index = 0
    for bit in bits:
        positions = [selector[sample_index], selector[sample_index + 1]]
        sample_index += 2
        current = (samples[positions[0]] & 1) ^ (samples[positions[1]] & 1)
        if current != bit:
            pos = positions[0]
            samples[pos] = samples[pos] + 1 if samples[pos] < 32767 else samples[pos] - 1
    with wave.open(str(path), "wb") as stream:
        stream.setnchannels(1)
        stream.setsampwidth(2)
        stream.setframerate(8000)
        frames = bytearray()
        for sample in samples:
            frames.extend(int(sample).to_bytes(2, "little", signed=True))
        stream.writeframes(bytes(frames))


def _write_native_steghide_bmp(path: Path, payload: bytes, *, password: str) -> None:
    width = 96
    height = 96
    row_bytes = width * 3
    stride = (row_bytes + 3) & ~3
    pixels = bytearray(stride * height)
    for index in range(width * height):
        base = (index // width) * stride + (index % width) * 3
        pixels[base] = (index * 17) & 0xFE
        pixels[base + 1] = (index * 31) & 0xFE
        pixels[base + 2] = (index * 47) & 0xFE
    bits = _build_steghide_bits(payload, password=password, encrypted=False)
    selector = _SteghideSelector(width * height, password)
    sample_index = 0
    for bit_index in range(0, len(bits), 2):
        target = bits[bit_index] | ((bits[bit_index + 1] if bit_index + 1 < len(bits) else 0) << 1)
        first = selector[sample_index]
        second = selector[sample_index + 1]
        sample_index += 2
        second_value = _bmp24_evalue(pixels, width, stride, second)
        _set_bmp24_evalue(pixels, width, stride, first, (target - second_value) % 4)
    file_size = 54 + len(pixels)
    header = bytearray()
    header.extend(b"BM")
    header.extend(file_size.to_bytes(4, "little"))
    header.extend((0).to_bytes(4, "little"))
    header.extend((54).to_bytes(4, "little"))
    header.extend((40).to_bytes(4, "little"))
    header.extend(width.to_bytes(4, "little", signed=True))
    header.extend(height.to_bytes(4, "little", signed=True))
    header.extend((1).to_bytes(2, "little"))
    header.extend((24).to_bytes(2, "little"))
    header.extend((0).to_bytes(4, "little"))
    header.extend(len(pixels).to_bytes(4, "little"))
    header.extend((2835).to_bytes(4, "little"))
    header.extend((2835).to_bytes(4, "little"))
    header.extend((0).to_bytes(4, "little"))
    header.extend((0).to_bytes(4, "little"))
    path.write_bytes(bytes(header + pixels))


def _bmp24_evalue(pixels: bytearray, width: int, stride: int, position: int) -> int:
    base = (position // width) * stride + (position % width) * 3
    blue = pixels[base] & 1
    green = pixels[base + 1] & 1
    red = pixels[base + 2] & 1
    return ((red ^ green) << 1) | (red ^ blue)


def _set_bmp24_evalue(
    pixels: bytearray, width: int, stride: int, position: int, value: int
) -> None:
    base = (position // width) * stride + (position % width) * 3
    pixels[base] = (pixels[base] & 0xFE) | (value & 1)
    pixels[base + 1] = (pixels[base + 1] & 0xFE) | ((value >> 1) & 1)
    pixels[base + 2] &= 0xFE


def _write_native_steghide_au(path: Path, payload: bytes, *, password: str) -> None:
    bits = _build_steghide_bits(payload, password=password, encrypted=False)
    samples = bytearray((index * 29) & 0xFE for index in range(max(4096, len(bits) * 4)))
    selector = _SteghideSelector(len(samples), password)
    sample_index = 0
    for bit in bits:
        first = selector[sample_index]
        second = selector[sample_index + 1]
        sample_index += 2
        if ((samples[first] & 1) ^ (samples[second] & 1)) != bit:
            samples[first] ^= 1
    header = b".snd" + (24).to_bytes(4, "big") + len(samples).to_bytes(4, "big")
    header += (2).to_bytes(4, "big") + (8000).to_bytes(4, "big") + (1).to_bytes(4, "big")
    path.write_bytes(header + samples)


def _write_native_steghide_jpeg(path: Path, payload: bytes, *, password: str) -> None:
    cover = path.with_name("cover.jpg")
    pixels = np.random.default_rng(1337).integers(0, 256, (96, 96, 3), dtype=np.uint8)
    Image.fromarray(pixels).save(cover, quality=95)
    image = _read_jpeg_dct_image(cover)
    positions = [
        (component_index, row_index, coeff_index)
        for component_index, component in enumerate(image.coefficients)
        for row_index, row in enumerate(component)
        for coeff_index, coeff in enumerate(row)
        if coeff != 0
    ]
    bits = _build_steghide_bits(payload, password=password, encrypted=False)
    if len(positions) < len(bits) * 3:
        raise AssertionError("synthetic JPEG does not have enough non-zero coefficients")
    selector = _SteghideSelector(len(positions), password)
    sample_index = 0
    for bit in bits:
        group = [positions[selector[sample_index + offset]] for offset in range(3)]
        sample_index += 3
        current = sum(abs(image.coefficients[c][r][i]) & 1 for c, r, i in group) & 1
        if current != bit:
            c, r, i = group[0]
            coeff = image.coefficients[c][r][i]
            image.coefficients[c][r][i] = coeff + 1 if coeff > 0 else coeff - 1
    _write_jpeg_dct_image(image, path)


def _build_steghide_bits(payload: bytes, *, password: str, encrypted: bool) -> list[int]:
    plain: list[int] = []
    _append_value(plain, 0, 1)  # compression flag
    _append_value(plain, 0, 1)  # checksum flag
    _append_value(plain, 0, 8)  # empty embedded filename
    plain.extend(_bits_from_bytes(payload))
    main: list[int] = []
    _append_value(main, 0x73688D, 24)
    _append_value(main, 0, 1)  # version terminator for version 0
    if encrypted:
        _append_value(main, 2, 5)  # rijndael-128
        _append_value(main, 1, 3)  # cbc
        _append_value(main, len(plain), 32)
        padded = plain[:]
        while len(padded) % 128:
            padded.append(0)
        iv = bytes(range(16))
        key = _mcrypt_md5_key(password, 16)
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(_bytes_from_bits(padded))
        main.extend(_bits_from_bytes(iv + ciphertext))
    else:
        _append_value(main, 0, 5)
        _append_value(main, 0, 3)
        _append_value(main, len(plain), 32)
        main.extend(plain)
    return main


def _append_value(bits: list[int], value: int, width: int) -> None:
    for bit_index in range(width):
        bits.append((value >> bit_index) & 1)


if __name__ == "__main__":
    unittest.main()
