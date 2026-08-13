from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.text_whitespace import (
    encode_whitespace_text,
    make_print_program,
    render_whitespace,
    run_whitespace,
)


class TextWhitespaceTest(unittest.TestCase):
    def test_run_generated_program_prints_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "flag.ws"
            output = root / "flag.txt"
            program.write_text(make_print_program(b"flag{whitespace}"), encoding="utf-8")

            result = run_whitespace(program, output)

            self.assertEqual(result.operation, "text.whitespace.run")
            self.assertEqual(output.read_bytes(), b"flag{whitespace}")
            self.assertEqual(result.stdout, "flag{whitespace}")
            self.assertGreater(result.instructions, 1)

    def test_non_whitespace_characters_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "commented.txt"
            clean = make_print_program(b"OK")
            noisy = "visible comment" + clean[:5] + "ignored" + clean[5:]
            program.write_text(noisy, encoding="utf-8")

            result = run_whitespace(program)

            self.assertEqual(result.stdout, "OK")

    def test_encode_payload_roundtrip_binary_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload.bin"
            program = root / "payload.ws"
            output = root / "payload.out"
            payload.write_bytes(bytes([0, 1, 0x7F, 0x80, 0xFF]))

            encode_result = encode_whitespace_text(program, payload_path=payload)
            run_result = run_whitespace(program, output)

            self.assertEqual(encode_result.operation, "text.whitespace.encode")
            self.assertEqual(run_result.operation, "text.whitespace.run")
            self.assertEqual(output.read_bytes(), payload.read_bytes())

    def test_render_visible_stl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "flag.ws"
            visible = root / "visible.txt"
            program.write_text(make_print_program(b"A"), encoding="utf-8")

            result = render_whitespace(program, visible)

            self.assertEqual(result.operation, "text.whitespace.show")
            rendered = visible.read_text(encoding="utf-8")
            self.assertIn("S", rendered)
            self.assertIn("T", rendered)
            self.assertIn("L", rendered)

    def test_cli_text_whitespace_run_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "flag.ws"
            output = root / "flag.txt"
            program.write_text(make_print_program(b"flag{cli_ws}"), encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "text",
                        "whitespace",
                        "run",
                        str(program),
                        "-o",
                        str(output),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["operation"], "text.whitespace.run")
            self.assertEqual(output.read_text(encoding="utf-8"), "flag{cli_ws}")

    def test_cli_text_whitespace_encode_then_run_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "flag.ws"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                encode_code = main(
                    ["text", "ws", "encode", "--text", "hi", "-o", str(program)]
                )
            run_stdout = io.StringIO()
            with contextlib.redirect_stdout(run_stdout):
                run_code = main(["text", "ws", "decode", str(program)])

            self.assertEqual(encode_code, 0)
            self.assertEqual(run_code, 0)
            self.assertEqual(run_stdout.getvalue(), "hi")


if __name__ == "__main__":
    unittest.main()
