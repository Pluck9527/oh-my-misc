from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.pixeljihad import (
    brute_pixeljihad_images,
    decode_pixeljihad_images,
    encode_pixeljihad_bytes,
    encode_pixeljihad_image,
)


class PixelJihadTest(unittest.TestCase):
    def test_empty_password_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            encoded = root / "encoded.png"
            Image.new("RGBA", (64, 64), (40, 80, 120, 255)).save(source)

            encode_result = encode_pixeljihad_image(
                source,
                encoded,
                "flag{PixelJihad_empty_password}",
            )
            decode_result = decode_pixeljihad_images([encoded])

            self.assertEqual(encode_result.operation, "image.pixeljihad.encode")
            self.assertEqual(decode_result.operation, "image.pixeljihad.decode")
            self.assertEqual(decode_result.text, "flag{PixelJihad_empty_password}")
            self.assertIn('{"text":"flag{PixelJihad_empty_password}"}', decode_result.raw_text)
            self.assertEqual(decode_result.messages[0]["status"], "text")

    def test_batch_decode_writes_joined_text_in_natural_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            carrier = root / "carrier.png"
            Image.new("RGBA", (32, 32), (0, 0, 0, 255)).save(carrier)
            pairs = (("frame-10.png", "B"), ("frame-2.png", "A"))
            inputs: list[Path] = []
            for name, text in pairs:
                output = root / name
                encode_pixeljihad_image(carrier, output, text)
                inputs.append(output)

            joined = root / "joined.txt"
            result = decode_pixeljihad_images(inputs, output_path=joined)

            self.assertEqual(result.text, "AB")
            self.assertEqual(joined.read_text(encoding="utf-8"), "AB")
            self.assertEqual([Path(item["input_path"]).name for item in result.messages], ["frame-2.png", "frame-10.png"])

    def test_cli_json_decode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            encoded = root / "encoded.png"
            Image.new("RGB", (48, 48), "white").save(source)
            encode_pixeljihad_image(source, encoded, "hello")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "pixeljihad",
                        "decode",
                        str(encoded),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.pixeljihad.decode")
            self.assertEqual(payload["text"], "hello")
            self.assertEqual(payload["messages"][0]["text"], "hello")

    def test_cli_decode_uses_custom_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            encoded = root / "encoded.png"
            words = root / "words.txt"
            output = root / "decoded.txt"
            image = Image.new("RGBA", (64, 64), (12, 34, 56, 255))
            colors = bytearray(image.tobytes())
            encode_pixeljihad_bytes(
                colors,
                json.dumps({"text": "flag{pixeljihad_wordlist}"}, separators=(",", ":")),
                password="letmein",
            )
            Image.frombytes("RGBA", image.size, bytes(colors)).save(encoded)
            words.write_text("bad\nletmein\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "pixeljihad",
                        "decode",
                        str(encoded),
                        "--wordlist",
                        str(words),
                        "--contains",
                        "flag{",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.pixeljihad.decode")
            self.assertEqual(payload["found_password"], "letmein")
            self.assertEqual(payload["attempts"], 2)
            self.assertEqual(payload["text"], "flag{pixeljihad_wordlist}")
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{pixeljihad_wordlist}")

    def test_brute_pixeljihad_images_returns_first_matching_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            encoded = root / "encoded.png"
            words = root / "words.txt"
            image = Image.new("RGBA", (64, 64), (90, 80, 70, 255))
            colors = bytearray(image.tobytes())
            encode_pixeljihad_bytes(colors, '{"text":"wordlist-hit"}', password="secret")
            Image.frombytes("RGBA", image.size, bytes(colors)).save(encoded)
            words.write_text("guess\nsecret\n", encoding="utf-8")

            result = brute_pixeljihad_images([encoded], words, contains="wordlist")

            self.assertEqual(result.found_password, "secret")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(result.text, "wordlist-hit")


if __name__ == "__main__":
    unittest.main()
