from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.image_steganography import (
    IMAGE_STEGANOGRAPHY_ITERATIONS,
    IMAGE_STEGANOGRAPHY_SALT,
    decode_difference_payload,
    decode_enlarge_payload,
    encode_difference_payload,
    encode_enlarge_payload,
    extract_image_steganography,
    hide_image_steganography,
    inspect_image_steganography,
)


class ImageSteganographyNativeTest(unittest.TestCase):
    def test_enlarge_roundtrip_with_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            stego = root / "stego.png"
            output = root / "payload.bin"
            _write_cover(cover, size=(12, 10))
            payload = b"flag{image_steg}\x00\x01tail"

            hide_result = hide_image_steganography(
                cover,
                stego,
                text=payload.decode("latin1"),
                password="p@ss",
                mode="enlarge",
            )
            extract_result = extract_image_steganography(
                stego,
                output,
                password="p@ss",
                mode="enlarge",
            )

            self.assertEqual(hide_result.operation, "image.image-steganography.hide")
            self.assertEqual(hide_result.width, 24)
            self.assertEqual(hide_result.height, 20)
            self.assertTrue(extract_result.marker_found)
            self.assertEqual(output.read_bytes(), payload)

    def test_difference_roundtrip_requires_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            stego = root / "diff.png"
            output = root / "payload.bin"
            _write_cover(cover, size=(8, 8))
            payload = b"flag{diff_mode}"

            result = hide_image_steganography(
                cover,
                stego,
                text=payload.decode("ascii"),
                mode="difference",
            )
            extract_result = extract_image_steganography(
                stego,
                output,
                mode="difference",
                reference_path=cover,
            )

            self.assertEqual(result.width, 8)
            self.assertEqual(result.height, 8)
            self.assertEqual(extract_result.reference_path, str(cover))
            self.assertEqual(output.read_bytes(), payload)

    def test_low_level_enlarge_preserves_zeros_across_planes(self) -> None:
        cover = _cover_image(size=(2, 2))
        payload = b"ABCD\x00\x00EF"
        stego = encode_enlarge_payload(payload, cover)
        decoded = decode_enlarge_payload(stego)
        self.assertEqual(decoded, payload)

    def test_low_level_difference_byte_mapping(self) -> None:
        cover = _cover_image(size=(16, 1))
        payload = bytes(range(16))
        stego = encode_difference_payload(payload, cover)
        decoded = decode_difference_payload(cover, stego, auto_trim=True)
        self.assertEqual(decoded, payload)

    def test_cli_json_and_inspect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.png"
            stego = root / "stego.png"
            output = root / "payload.out"
            _write_cover(cover, size=(10, 10))

            self.assertEqual(
                main(
                    [
                        "image",
                        "image-steganography",
                        "hide",
                        str(cover),
                        "--text",
                        "flag{cli_image_steg}",
                        "-o",
                        str(stego),
                    ]
                ),
                0,
            )
            inspect_result = inspect_image_steganography(stego)
            self.assertTrue(inspect_result.marker_found)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "image-steg",
                        "extract",
                        str(stego),
                        "-o",
                        str(output),
                        "--json",
                    ]
                )
            data = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(data["operation"], "image.image-steganography.extract")
            self.assertEqual(data["mode"], "enlarge")
            self.assertEqual(output.read_bytes(), b"flag{cli_image_steg}")

    def test_reverse_constants_match_attached_binary(self) -> None:
        self.assertEqual(
            IMAGE_STEGANOGRAPHY_SALT,
            bytes([0, 0, 1, 2, 3, 4, 5, 6, 241, 240, 238, 33, 34, 69]),
        )
        self.assertEqual(IMAGE_STEGANOGRAPHY_ITERATIONS, 1000)


def _write_cover(path: Path, *, size: tuple[int, int] = (16, 16)) -> None:
    _cover_image(size=size).save(path)


def _cover_image(*, size: tuple[int, int]) -> Image.Image:
    width, height = size
    image = Image.new("RGB", size)
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            pixels[x, y] = (32 + (x * 7 + y * 3) % 80, 96 + (x * 5 + y * 11) % 64, 40 + (x * 13 + y * 17) % 80)
    return image


if __name__ == "__main__":
    unittest.main()
