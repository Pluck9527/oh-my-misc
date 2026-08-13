from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import wave
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.deepsound import analyze_deepsound, extract_deepsound, hide_deepsound


class DeepSoundTest(unittest.TestCase):
    def test_hide_analyze_extract_text_normal_quality(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.wav"
            stego = root / "stego.wav"
            output = root / "hidden.txt"
            _write_wav(cover)

            hidden = hide_deepsound(
                cover,
                stego,
                text="flag{deepsound}",
                text_name="flag.txt",
                quality="normal",
            )
            analyzed = analyze_deepsound(stego)
            extracted = extract_deepsound(stego, output)

            self.assertEqual(hidden.operation, "stego.deepsound.hide")
            self.assertTrue(analyzed.found)
            self.assertEqual(analyzed.quality, "normal")
            self.assertFalse(analyzed.encrypted)
            self.assertEqual(analyzed.files[0]["name"], "flag.txt")
            self.assertEqual(extracted.operation, "stego.deepsound.extract")
            self.assertEqual(output.read_bytes(), b"flag{deepsound}")
            self.assertEqual(extracted.findings[0]["kind"], "flag")

    def test_hide_extract_multiple_files_high_quality_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.wav"
            stego = root / "stego.wav"
            first = root / "a.bin"
            second = root / "second.longextension"
            out_dir = root / "out"
            _write_wav(cover, frames=8000)
            first.write_bytes(b"PK\x03\x04demo")
            second.write_bytes(b"hello")

            hidden = hide_deepsound(cover, stego, payload_paths=[first, second], quality="high")
            extracted = extract_deepsound(stego, out_dir)

            self.assertEqual(hidden.quality, "high")
            self.assertEqual(len(extracted.files), 2)
            self.assertEqual((out_dir / "a.bin").read_bytes(), b"PK\x03\x04demo")
            self.assertEqual((out_dir / "second.long").read_bytes(), b"hello")
            self.assertEqual(extracted.findings[0]["kind"], "zip")

    def test_cli_deepsound_extract_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.wav"
            stego = root / "stego.wav"
            output = root / "out.txt"
            _write_wav(cover)
            hide_deepsound(cover, stego, text="hello", text_name="hello.txt")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "stego",
                        "deepsound",
                        "extract",
                        str(stego),
                        "-o",
                        str(output),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "stego.deepsound.extract")
            self.assertEqual(payload["quality"], "normal")
            self.assertEqual(output.read_bytes(), b"hello")


def _write_wav(path: Path, *, frames: int = 5000) -> None:
    samples = bytearray()
    for index in range(frames):
        value = (index * 13) & 0xFFFF
        samples.extend(value.to_bytes(2, "little"))
        samples.extend((value ^ 0xAAAA).to_bytes(2, "little"))
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(2)
        wav.setsampwidth(2)
        wav.setframerate(8000)
        wav.writeframes(bytes(samples))


if __name__ == "__main__":
    unittest.main()
