from __future__ import annotations

import contextlib
import io
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from PIL import Image, ImageDraw

from oh_my_misc.cli import main
from oh_my_misc.outguess import brute_outguess, extract_outguess, hide_outguess


class OutguessTest(unittest.TestCase):
    def test_extract_uses_key_and_writes_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = _fake_outguess(root)
            image = root / "outguess.jpg"
            output = root / "flag.txt"
            image.write_text("abc", encoding="utf-8")

            result = extract_outguess(image, output, key="abc", outguess_path=tool)

            self.assertEqual(result.operation, "image.outguess.extract")
            self.assertEqual(result.found_key, "abc")
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{abc}")

    def test_brute_wordlist_finds_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = _fake_outguess(root)
            image = root / "outguess.jpg"
            words = root / "words.txt"
            output = root / "flag.txt"
            image.write_text("secret", encoding="utf-8")
            words.write_text("bad\nsecret\n", encoding="utf-8")

            result = brute_outguess(
                image,
                words,
                output,
                outguess_path=tool,
                contains=b"flag{",
                include_empty=False,
            )

            self.assertEqual(result.operation, "image.outguess.brute")
            self.assertEqual(result.found_key, "secret")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{secret}")

    def test_hide_invokes_outguess_d_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = _fake_outguess(root)
            image = root / "cover.jpg"
            payload = root / "payload.txt"
            stego = root / "stego.jpg"
            image.write_text("cover", encoding="utf-8")
            payload.write_text("flag{embed}", encoding="utf-8")

            result = hide_outguess(image, stego, payload, key="abc", outguess_path=tool)

            self.assertEqual(result.operation, "image.outguess.hide")
            self.assertIn("key=abc", stego.read_text(encoding="utf-8"))
            self.assertIn("flag{embed}", stego.read_text(encoding="utf-8"))

    def test_native_jpeg_roundtrip_without_outguess_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            payload = root / "payload.bin"
            stego = root / "stego.jpg"
            output = root / "output.bin"
            _write_jpeg(cover)
            payload.write_bytes(b"flag{native_outguess_jpeg}")

            hide_result = hide_outguess(cover, stego, payload, key="abc", backend="native")
            extract_result = extract_outguess(stego, output, key="abc", backend="native")

            self.assertEqual(hide_result.operation, "image.outguess.hide-native")
            self.assertEqual(extract_result.operation, "image.outguess.extract-native")
            self.assertEqual(output.read_bytes(), b"flag{native_outguess_jpeg}")
            self.assertTrue(stego.read_bytes().startswith(b"\xff\xd8"))

    def test_native_pnm_roundtrip_without_outguess_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.ppm"
            payload = root / "payload.bin"
            stego = root / "stego.ppm"
            output = root / "output.bin"
            _write_ppm(cover, 180, 180)
            payload.write_bytes(b"flag{native_outguess_pnm}")

            hide_result = hide_outguess(cover, stego, payload, key="abc", backend="native")
            extract_result = extract_outguess(stego, output, key="abc", backend="native")

            self.assertEqual(hide_result.operation, "image.outguess.hide-native")
            self.assertEqual(extract_result.operation, "image.outguess.extract-native")
            self.assertEqual(output.read_bytes(), b"flag{native_outguess_pnm}")
            self.assertTrue(stego.read_bytes().startswith(b"P6\n180 180\n255\n"))

    def test_native_pnm_brute_finds_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.pnm"
            payload = root / "payload.txt"
            stego = root / "stego.pnm"
            words = root / "words.txt"
            output = root / "output.txt"
            _write_ppm(cover, 180, 180)
            payload.write_text("flag{native_brute}", encoding="utf-8")
            words.write_text("bad\nsecret\n", encoding="utf-8")
            hide_outguess(cover, stego, payload, key="secret", backend="native")

            result = brute_outguess(
                stego,
                words,
                output,
                contains=b"flag{",
                include_empty=False,
                backend="native",
            )

            self.assertEqual(result.operation, "image.outguess.brute-native")
            self.assertEqual(result.found_key, "secret")
            self.assertEqual(result.attempts, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{native_brute}")

    def test_cli_extract_wordlist_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = _fake_outguess(root)
            image = root / "outguess.jpg"
            words = root / "words.txt"
            output = root / "flag.txt"
            image.write_text("hunter2", encoding="utf-8")
            words.write_text("wrong\nhunter2\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image",
                        "outguess",
                        "extract",
                        str(image),
                        "--wordlist",
                        str(words),
                        "--no-empty",
                        "--outguess",
                        str(tool),
                        "--contains",
                        "flag{",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "image.outguess.brute")
            self.assertEqual(payload["found_key"], "hunter2")
            self.assertEqual(payload["attempts"], 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{hunter2}")


def _write_jpeg(path: Path) -> None:
    image = Image.new("RGB", (256, 256), "white")
    draw = ImageDraw.Draw(image)
    for offset in range(-256, 256, 9):
        draw.line((offset, 0, offset + 256, 256), fill=(offset % 255, 80, 180), width=2)
    for x in range(0, 256, 16):
        draw.rectangle((x, (x * 3) % 200, min(255, x + 12), min(255, (x * 3) % 200 + 30)), fill=(20, x % 255, 120))
    image.save(path, "JPEG", quality=95)


def _write_ppm(path: Path, width: int, height: int) -> None:
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            pixels.extend(((x * 3 + y) % 256, (x + y * 5) % 256, (x * 7 + y * 11) % 256))
    path.write_bytes(f"P6\n{width} {height}\n255\n".encode("ascii") + bytes(pixels))


def _fake_outguess(root: Path) -> Path:
    path = root / "outguess"
    path.write_text(
        textwrap.dedent(
            r'''
            #!/usr/bin/env python3
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            def value(flag):
                index = args.index(flag)
                return args[index + 1]
            key = value("-k") if "-k" in args else ""
            if "-r" in args:
                index = args.index("-r")
                image = Path(args[index + 1])
                output = Path(args[index + 2])
                expected = image.read_text(encoding="utf-8")
                if key != expected:
                    print("extract failed", file=sys.stderr)
                    raise SystemExit(1)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(f"flag{{{key or 'empty_outguess'}}}", encoding="utf-8")
                raise SystemExit(0)
            if "-d" in args:
                payload = Path(value("-d"))
                input_path = Path(args[-2])
                output = Path(args[-1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    f"stego key={key} cover={input_path.read_text(encoding='utf-8')} payload={payload.read_text(encoding='utf-8')}",
                    encoding="utf-8",
                )
                raise SystemExit(0)
            print("unsupported", file=sys.stderr)
            raise SystemExit(2)
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


if __name__ == "__main__":
    unittest.main()
