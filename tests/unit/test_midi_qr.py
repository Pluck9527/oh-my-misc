from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from oh_my_misc.cli import main
from oh_my_misc.midi_qr import MidiEvent, render_midi_qr, write_midi_from_events


class MidiQrTest(unittest.TestCase):
    def test_hex_log_renders_note_grid_and_rebuilds_midi(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "events.txt"
            png = root / "qr.png"
            midi = root / "recovered.mid"
            log.write_text(_sample_hex_log(), encoding="utf-8")

            result = render_midi_qr(log, png, cell_size=4, midi_output_path=midi)
            image = Image.open(png)

            self.assertEqual(result.source, "log")
            self.assertEqual(result.rows, 3)
            self.assertEqual(result.columns, 3)
            self.assertEqual(result.note_count, 3)
            self.assertEqual(result.note_on_count, 6)
            self.assertEqual(image.size, (12, 12))
            self.assertEqual(image.getpixel((0, 0)), 0)
            self.assertEqual(image.getpixel((4, 0)), 255)
            self.assertEqual(image.getpixel((8, 0)), 0)
            self.assertEqual(midi.read_bytes()[:4], b"MThd")
            self.assertGreater(result.midi_written_bytes, 20)

    def test_standard_midi_input_auto_detects_and_renders(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            midi = root / "sample.mid"
            png = root / "qr.png"
            events = [
                MidiEvent(10.000, "note_on", 60, 64, channel=0),
                MidiEvent(10.001, "note_on", 64, 64, channel=0),
                MidiEvent(10.020, "note_on", 62, 64, channel=0),
                MidiEvent(10.040, "note_on", 60, 64, channel=0),
                MidiEvent(10.041, "note_on", 62, 64, channel=0),
                MidiEvent(10.042, "note_on", 64, 64, channel=0),
            ]
            write_midi_from_events(events, midi, min_duration_ms=5.0)

            result = render_midi_qr(midi, png, source="auto", row_gap_seconds=0.005, cell_size=2)

            self.assertEqual(result.source, "midi")
            self.assertEqual(result.rows, 3)
            self.assertEqual(result.columns, 3)
            self.assertEqual(Image.open(png).size, (6, 6))

    def test_cli_midi_qr_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "events.txt"
            png = root / "qr.png"
            midi = root / "recovered.mid"
            log.write_text(_sample_hex_log(), encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "audio",
                        "midi-qr",
                        str(log),
                        "-o",
                        str(png),
                        "--midi-output",
                        str(midi),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "audio.midi-qr.render")
            self.assertEqual(payload["source"], "log")
            self.assertEqual(payload["rows"], 3)
            self.assertEqual(payload["columns"], 3)
            self.assertEqual(Path(payload["output_path"]).read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(Path(payload["midi_output_path"]).read_bytes()[:4], b"MThd")


def _sample_hex_log() -> str:
    return (
        "1722159321.000000\t903c40\n"
        "1722159321.001000\t904040\n"
        "1722159321.006000\t803c00\n"
        "1722159321.007000\t804000\n"
        "1722159321.020000\t903e40\n"
        "1722159321.026000\t803e00\n"
        "1722159321.040000\t903c40\n"
        "1722159321.041000\t903e40\n"
        "1722159321.042000\t904040\n"
        "1722159321.050000\t803c00\n"
        "1722159321.051000\t803e00\n"
        "1722159321.052000\t804000"
    )


if __name__ == "__main__":
    unittest.main()
