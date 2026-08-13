from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import wave
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.silenteye import extract_silenteye, hide_silenteye


class SilentEyeTest(unittest.TestCase):
    def test_bmp_hide_extract_text_default_encrypted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.bmp"
            stego = root / "stego.bmp"
            output = root / "out.txt"
            Image.new("RGB", (80, 80), (120, 121, 122)).save(cover)

            hidden = hide_silenteye(cover, stego, text="flag{silenteye}", password="silenteye")
            result = extract_silenteye(stego, output, password="silenteye")

            self.assertEqual(hidden.operation, "stego.silenteye.hide")
            self.assertEqual(result.operation, "stego.silenteye.extract")
            self.assertEqual(result.data_format, "utf8")
            self.assertEqual(output.read_bytes(), b"flag{silenteye}")
            self.assertEqual(result.findings[0]["kind"], "flag")

    def test_wav_hide_extract_file_uncompressed_inline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.wav"
            payload = root / "secret.bin"
            stego = root / "stego.wav"
            output = root / "out.bin"
            payload.write_bytes(b"PK\x03\x04demo")
            _write_wav(cover)

            hidden = hide_silenteye(
                cover,
                stego,
                payload_path=payload,
                compress=False,
                bits=2,
                channels=1,
                distribution="inline",
                header_position="beginning",
            )
            result = extract_silenteye(
                stego,
                output,
                compressed="no",
                bits=2,
                channels=1,
                distribution="inline",
                header_position="beginning",
            )

            self.assertEqual(hidden.carrier_format, "wav")
            self.assertEqual(result.payload_name, "secret.bin")
            self.assertEqual(output.read_bytes(), b"PK\x03\x04demo")
            self.assertEqual(result.findings[0]["kind"], "zip")

    def test_cli_silenteye_extract_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.bmp"
            stego = root / "stego.bmp"
            output = root / "out.txt"
            Image.new("RGB", (80, 80), (1, 2, 3)).save(cover)
            hide_silenteye(cover, stego, text="hello", password="silenteye")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "stego",
                        "silenteye",
                        "extract",
                        str(stego),
                        "--password",
                        "silenteye",
                        "-o",
                        str(output),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "stego.silenteye.extract")
            self.assertEqual(output.read_bytes(), b"hello")


def _write_wav(path: Path) -> None:
    frames = bytearray()
    for index in range(5000):
        value = (index * 7) & 0xFFFF
        frames.extend(value.to_bytes(2, "little"))
        frames.extend((value ^ 0x5555).to_bytes(2, "little"))
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(2)
        wav.setsampwidth(2)
        wav.setframerate(8000)
        wav.writeframes(bytes(frames))


if __name__ == "__main__":
    unittest.main()
