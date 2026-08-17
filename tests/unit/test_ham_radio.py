from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.ham_radio import decode_ham_radio, encode_ax25_afsk1200_wav, inspect_ham_radio


class HamRadioTest(unittest.TestCase):
    def test_encode_decode_native_afsk1200_aprs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav = root / "latlong.wav"
            output = root / "decoded.txt"
            encode_ax25_afsk1200_wav(
                wav,
                source="N0CALL",
                destination="APRS",
                info="flag{ham_radio}",
            )

            result = decode_ham_radio(wav, output)

            self.assertEqual(result.operation, "audio.ham.decode")
            self.assertEqual(result.valid_frames, 1)
            self.assertEqual(result.packets[0]["source"], "N0CALL")
            self.assertEqual(result.packets[0]["destination"], "APRS")
            self.assertEqual(result.packets[0]["info"], "flag{ham_radio}")
            self.assertEqual(output.read_text(encoding="utf-8"), "N0CALL>APRS:flag{ham_radio}\n")
            self.assertEqual(result.findings[0]["kind"], "flag")

    def test_inspect_reports_frames_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav = root / "aprs.wav"
            encode_ax25_afsk1200_wav(
                wav,
                source="K1ABC",
                destination="CQ",
                path=["WIDE1-1"],
                info="CQ TEST",
                sample_rate=22_050,
            )

            result = inspect_ham_radio(wav)

            self.assertEqual(result.operation, "audio.ham.inspect")
            self.assertEqual(result.sample_rate, 22_050)
            self.assertGreaterEqual(result.valid_frames, 1)
            self.assertIn("K1ABC>CQ,WIDE1-1:CQ TEST", result.messages)

    def test_cli_ham_decode_json_and_raw_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav = root / "aprs.wav"
            output = root / "decoded.txt"
            raw = root / "latlong.raw"
            encode_ax25_afsk1200_wav(wav, info="flag{cli_ham}")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "audio",
                        "ham",
                        "decode",
                        str(wav),
                        "-o",
                        str(output),
                        "--raw-output",
                        str(raw),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "audio.ham.decode")
            self.assertEqual(payload["valid_frames"], 1)
            self.assertTrue(raw.is_file())
            self.assertIn("flag{cli_ham}", output.read_text(encoding="utf-8"))

    def test_multimon_backend_alias_stays_native(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wav = root / "aprs.wav"
            output = root / "decoded.txt"
            raw = root / "latlong.raw"
            encode_ax25_afsk1200_wav(wav, info="flag{native_alias}")

            result = decode_ham_radio(
                wav,
                output,
                backend="multimon",
                raw_output=raw,
                multimon=root / "ignored-multimon",
            )

            self.assertEqual(result.backend, "native")
            self.assertIsNone(result.executable)
            self.assertTrue(raw.is_file())
            self.assertIn("flag{native_alias}", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
