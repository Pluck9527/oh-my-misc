from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import Blowfish
from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.jphs import (
    _JphsState,
    brute_jphs,
    embed_jphs_payload_in_coefficients,
    extract_jphs,
    extract_jphs_payload_from_coefficients,
    hide_jphs,
)
from oh_my_misc.jphs_ltable import TAIL1


class JphsWrapperTest(unittest.TestCase):
    def test_extract_supports_empty_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            image = root / "stego.jpg"
            payload = root / "payload.txt"
            output = root / "hidden.txt"
            _write_jphs_cover(cover)
            payload.write_text("flag{empty_jphs}", encoding="utf-8")
            hide_jphs(cover, image, payload, password="", jphide_path=root / "ignored", backend="tool")

            result = extract_jphs(image, output, jpseek_path=root / "ignored", backend="tool")

            self.assertEqual(result.operation, "image.jphs.extract-python")
            self.assertEqual(result.tool_path, "python")
            self.assertEqual(result.found_password, None)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{empty_jphs}")

    def test_extract_cli_accepts_custom_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            image = root / "stego.jpg"
            embedded = root / "payload.txt"
            wordlist = root / "words.txt"
            output = root / "hidden.txt"
            _write_jphs_cover(cover)
            embedded.write_text("flag{secret_jphs}", encoding="utf-8")
            hide_jphs(cover, image, embedded, password="secret")
            wordlist.write_text("bad\nsecret\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "jphs",
                        "extract",
                        str(image),
                        "--wordlist",
                        str(wordlist),
                        "--no-empty",
                        "--contains",
                        "flag{",
                        "--backend",
                        "tool",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.jphs.brute-python")
            self.assertEqual(payload["tool_path"], "python")
            self.assertEqual(payload["found_password"], "secret")
            self.assertEqual(payload["attempts"], 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{secret_jphs}")

    def test_brute_tries_empty_password_first_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            image = root / "stego.jpg"
            embedded = root / "payload.txt"
            wordlist = root / "words.txt"
            output = root / "hidden.txt"
            _write_jphs_cover(cover)
            embedded.write_text("flag{empty_jphs}", encoding="utf-8")
            hide_jphs(cover, image, embedded, password="")
            wordlist.write_text("secret\n", encoding="utf-8")

            result = brute_jphs(
                image,
                wordlist,
                output,
                jpseek_path=root / "ignored-jpseek",
                contains=b"empty",
                backend="tool",
            )

            self.assertEqual(result.operation, "image.jphs.brute-python")
            self.assertEqual(result.tool_path, "python")
            self.assertEqual(result.found_password, "")
            self.assertEqual(result.attempts, 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{empty_jphs}")

    def test_hide_tool_alias_uses_python_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            payload = root / "payload.bin"
            stego = root / "stego.jpg"
            output = root / "out.bin"
            _write_jphs_cover(cover)
            payload.write_bytes(b"secret-data")

            result = hide_jphs(
                cover,
                stego,
                payload,
                password="pass",
                jphide_path=root / "ignored-jphide",
                backend="tool",
            )
            extract_jphs(stego, output, password="pass")

            self.assertEqual(result.operation, "image.jphs.hide-python")
            self.assertEqual(result.tool_path, "python")
            self.assertTrue(result.password_used)
            self.assertEqual(output.read_bytes(), b"secret-data")

    def test_jphs05_path_args_route_to_python_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            image = root / "stego.jpg"
            embedded = root / "payload.txt"
            output = root / "hidden.txt"
            _write_jphs_cover(cover)
            embedded.write_text("flag{secret_jphs}", encoding="utf-8")
            hide_jphs(cover, image, embedded, password="secret")

            result = extract_jphs(
                image,
                output,
                password="secret",
                jpseek_path=root / "jpseek.exe",
                wine_path=root / "wine",
                backend="tool",
            )

            self.assertEqual(result.tool_path, "python")
            self.assertEqual(result.runner_path, None)
            self.assertEqual(result.found_password, "secret")
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{secret_jphs}")

    def test_pure_python_extracts_synthetic_coefficients(self) -> None:
        payload = b"flag{pure_jphs}"
        password = "secret"
        coefficients = _synthetic_coefficients()
        _embed_synthetic_jphs_payload(coefficients, payload, password)

        extracted = extract_jphs_payload_from_coefficients(coefficients, password=password)

        self.assertEqual(extracted, payload)

    def test_pure_python_hide_extracts_baseline_jpeg(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            payload = root / "payload.bin"
            stego = root / "stego.jpg"
            output = root / "out.bin"
            Image.new("RGB", (96, 96), (90, 140, 190)).save(cover, "JPEG", quality=90)
            payload.write_bytes(b"flag{python_jphs_roundtrip}")

            hide_result = hide_jphs(cover, stego, payload, password="secret")
            extract_result = extract_jphs(stego, output, password="secret")

            self.assertEqual(hide_result.operation, "image.jphs.hide-python")
            self.assertEqual(extract_result.operation, "image.jphs.extract-python")
            with Image.open(stego) as reopened:
                self.assertEqual(reopened.size, (96, 96))
            self.assertEqual(output.read_bytes(), b"flag{python_jphs_roundtrip}")

    def test_pure_python_embeds_synthetic_coefficients(self) -> None:
        coefficients = _synthetic_coefficients()

        embed_jphs_payload_in_coefficients(coefficients, b"flag{embed}", password="secret")
        extracted = extract_jphs_payload_from_coefficients(coefficients, password="secret")

        self.assertEqual(extracted, b"flag{embed}")


def _write_jphs_cover(path: Path) -> None:
    Image.new("RGB", (96, 96), (90, 140, 190)).save(path, "JPEG", quality=90)


def _synthetic_coefficients() -> list[list[list[int]]]:
    components: list[list[list[int]]] = []
    for _ in range(3):
        components.append([[1] * (16 * 64) for _ in range(24)])
    for index, value in enumerate((3, 7, 11, 19, 23, 29, 31, 37)):
        components[0][0][index] = value
    return components


def _embed_synthetic_jphs_payload(
    coefficients: list[list[list[int]]],
    payload: bytes,
    password: str,
) -> None:
    state = _JphsState(coefficients, password)
    cipher = Blowfish.new(password.encode("utf-8"), Blowfish.MODE_ECB)
    iv = bytearray((coefficients[0][0][index] & 0xFF) for index in range(8))
    for _ in range(4):
        iv.append(iv[0])
        del iv[0]
    length_block = bytearray(cipher.encrypt(bytes(iv[:8])))
    length_block[0] = len(payload) >> 16
    length_block[1] = (len(payload) >> 8) & 0xFF
    length_block[2] = len(payload) & 0xFF
    encrypted_length = cipher.encrypt(bytes(length_block))
    for byte in encrypted_length:
        for bit_index in range(8):
            _put_synthetic_bit(state, (byte >> bit_index) & 1)
    state.tail = len(payload) * 8 - TAIL1
    state.tail_on = 0
    for byte in payload:
        for bit_index in range(8):
            data_bit = (byte >> (7 - bit_index)) & 1
            _put_synthetic_bit(state, data_bit ^ state.get_code_bit(1))
            state.tail -= 1


def _put_synthetic_bit(state: _JphsState, bit: int) -> None:
    word = state.get_word()
    state.coefficients[state.coef][state.lh][state.lw] = _merge_synthetic_word(
        word,
        bit,
        state.mode,
    )


def _merge_synthetic_word(word: int, bit: int, mode: int) -> int:
    if mode < 0:
        value = bit << 1
        if word > 0:
            return (word & ~2) | value
        return -(((-word) & ~2) | value)
    if word == 0:
        return bit
    if word in {-1, 1}:
        return bit * word
    if word > 0:
        return (word & ~1) | bit
    return -(((-word) & ~1) | bit)

if __name__ == "__main__":
    unittest.main()
