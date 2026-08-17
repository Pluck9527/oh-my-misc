from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.deegger import (
    BREAK_START,
    BREAK_STOP,
    create_cab_bytes,
    extract_cab_bytes,
    extract_deegger,
    find_deegger_payload,
    hide_deegger,
    inspect_deegger,
    list_cab_bytes,
)


class DeEggerNativeTest(unittest.TestCase):
    def test_single_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = root / "cover.jpg"
            payload = root / "secret.txt"
            stego = root / "stego.jpg"
            output = root / "extracted"
            host.write_bytes(b"\xff\xd8JFIF demo\xff\xd9")
            payload.write_bytes(b"flag{deegger_single}")

            hide_result = hide_deegger(host, stego, payload_paths=[payload])
            inspect_result = inspect_deegger(stego)
            extract_result = extract_deegger(stego, output)

            self.assertEqual(hide_result.operation, "stego.deegger.hide")
            self.assertEqual(hide_result.start_offset, len(host.read_bytes()))
            self.assertTrue(inspect_result.marker_found)
            self.assertEqual(inspect_result.extension, ".txt")
            self.assertEqual(extract_result.output_paths, [str(output.with_suffix(".txt"))])
            self.assertEqual(output.with_suffix(".txt").read_bytes(), b"flag{deegger_single}")

    def test_format_markers_and_inversion_match_reverse(self) -> None:
        host = b"HOST"
        payload = b"ABC"
        extension = b".bin\x00"
        carrier = host + BREAK_START + bytes(byte ^ 0xFF for byte in payload) + BREAK_STOP
        carrier += bytes(byte ^ 0xFF for byte in extension)
        found = find_deegger_payload(carrier)

        self.assertTrue(found.marker_found)
        self.assertEqual(found.start_offset, len(host))
        self.assertEqual(bytes(byte ^ 0xFF for byte in found.hidden_bytes), payload)

    def test_multi_file_cab_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = root / "cover.pdf"
            first = root / "a.txt"
            second = root / "b.bin"
            stego = root / "stego.pdf"
            output_dir = root / "out"
            host.write_bytes(b"%PDF-1.4\n%%EOF\n")
            first.write_bytes(b"alpha")
            second.write_bytes(b"beta")

            hide_deegger(host, stego, payload_paths=[first, second])
            inspect_result = inspect_deegger(stego)
            extract_result = extract_deegger(stego, output_dir, unpack=True)

            self.assertTrue(inspect_result.multi_file)
            self.assertEqual([entry["name"] for entry in inspect_result.entries or []], ["a.txt", "b.bin"])
            self.assertEqual(extract_result.operation, "stego.deegger.extract-files")
            self.assertEqual((output_dir / "a.txt").read_bytes(), b"alpha")
            self.assertEqual((output_dir / "b.bin").read_bytes(), b"beta")

    def test_cab_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one.txt"
            second = root / "two.dat"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            cab = create_cab_bytes([first, second])
            out = root / "cab-out"

            self.assertEqual([entry.name for entry in list_cab_bytes(cab)], ["one.txt", "two.dat"])
            extract_cab_bytes(cab, out)
            self.assertEqual((out / "one.txt").read_bytes(), b"one")
            self.assertEqual((out / "two.dat").read_bytes(), b"two")

    def test_cli_json_extract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = root / "cover.bin"
            payload = root / "payload.dat"
            stego = root / "stego.bin"
            output = root / "payload.out"
            host.write_bytes(b"carrier-data")
            payload.write_bytes(b"flag{cli_deegger}")

            self.assertEqual(
                main(
                    [
                        "stego",
                        "deegger",
                        "hide",
                        str(host),
                        "--payload",
                        str(payload),
                        "-o",
                        str(stego),
                    ]
                ),
                0,
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "stego",
                        "deegger",
                        "extract",
                        str(stego),
                        "-o",
                        str(output),
                        "--json",
                    ]
                )
            data = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(data["operation"], "stego.deegger.extract")
            self.assertEqual(data["extension"], ".dat")
            self.assertEqual(output.read_bytes(), b"flag{cli_deegger}")


if __name__ == "__main__":
    unittest.main()
