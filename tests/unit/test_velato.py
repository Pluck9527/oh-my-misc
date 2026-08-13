from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.velato import decode_velato, encode_velato_text, inspect_velato


class VelatoTest(unittest.TestCase):
    def test_encode_then_decode_printed_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            midi = root / "flag.mid"
            out = root / "flag.txt"

            encoded = encode_velato_text(midi, "flag{velato}")
            inspected = inspect_velato(midi)
            decoded = decode_velato(midi, out)

            self.assertEqual(encoded.printed_text, "flag{velato}")
            self.assertEqual(inspected.printed_text, "flag{velato}")
            self.assertEqual(decoded.printed_text, "flag{velato}")
            self.assertEqual(out.read_text(encoding="utf-8"), "flag{velato}")
            self.assertEqual(inspected.commands[0]["command"], "print")
            self.assertEqual(inspected.findings[0]["kind"], "flag")

    def test_cli_velato_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            midi = root / "hi.mid"
            out = root / "hi.txt"

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "audio",
                        "velato",
                        "encode",
                        "--text",
                        "Hi",
                        "-o",
                        str(midi),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "audio.velato.encode")
            self.assertEqual(payload["printed_text"], "Hi")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["audio", "velato", "decode", str(midi), "-o", str(out), "--json"])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "audio.velato.decode")
            self.assertEqual(payload["printed_text"], "Hi")
            self.assertEqual(out.read_text(encoding="utf-8"), "Hi")

    def test_upstream_hi_fixture_when_available(self) -> None:
        upstream = Path(".codex/velato-src/Programs/hi.mid")
        if not upstream.exists():
            self.skipTest("upstream Velato fixture not cloned")
        result = inspect_velato(upstream)
        self.assertEqual(result.printed_text, "Hi")


if __name__ == "__main__":
    unittest.main()
