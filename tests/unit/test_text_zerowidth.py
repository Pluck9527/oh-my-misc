from __future__ import annotations

import json
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.text_zerowidth import (
    DEFAULT_CHARS,
    decode_zero_width_binary,
    decode_zero_width_text,
    encode_zero_width_binary,
    encode_zero_width_text,
    extract_zero_width,
    hide_zero_width,
    inspect_zero_width,
    strip_zero_width_file,
)


def test_330k_binary_roundtrip_keeps_visible_text(tmp_path: Path) -> None:
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "stego.txt"
    output = tmp_path / "payload.bin"
    cover.write_text("hello visible world", encoding="utf-8")

    hide = hide_zero_width(cover, stego, text="flag{zero}", placement="spread")
    extract = extract_zero_width(stego, output)

    assert hide.char_codes == ["U+200C", "U+200D", "U+202C", "U+FEFF"]
    assert hide.hidden_chars == len(b"flag{zero}") * 4
    assert extract.hidden_chars == hide.hidden_chars
    assert output.read_bytes() == b"flag{zero}"
    assert inspect_zero_width(stego).hidden_chars == hide.hidden_chars


def test_330k_text_mode_matches_utf16_units() -> None:
    hidden = encode_zero_width_text("雪🙂", DEFAULT_CHARS)

    assert len(hidden) == 24
    assert decode_zero_width_text(hidden, DEFAULT_CHARS) == "雪🙂"


def test_custom_two_character_binary_roundtrip() -> None:
    chars = "\u200b\u200c"
    hidden = encode_zero_width_binary(b"AZ", chars)

    assert set(hidden) == set(chars)
    assert len(hidden) == 16
    assert decode_zero_width_binary(hidden, chars) == b"AZ"


def test_strip_removes_common_zero_width_chars(tmp_path: Path) -> None:
    src = tmp_path / "z.txt"
    dst = tmp_path / "clean.txt"
    src.write_text("a\u200bb\u200cc\u2063d", encoding="utf-8")

    result = strip_zero_width_file(src, dst)

    assert result.hidden_chars == 3
    assert dst.read_text(encoding="utf-8") == "abcd"


def test_cli_zerowidth_json_roundtrip_and_custom_chars(tmp_path: Path, capsys) -> None:
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "stego.txt"
    output = tmp_path / "payload.bin"
    cover.write_text("plain text", encoding="utf-8")

    assert (
        main(
            [
                "text",
                "zwc",
                "hide",
                str(cover),
                "--text",
                "flag{cli}",
                "--chars",
                "U+200B,U+200C",
                "-o",
                str(stego),
                "--json",
            ]
        )
        == 0
    )
    hide_data = json.loads(capsys.readouterr().out)
    assert hide_data["alphabet"] == "custom"
    assert hide_data["char_codes"] == ["U+200B", "U+200C"]

    assert (
        main(
            [
                "text",
                "zero-width",
                "extract",
                str(stego),
                "--chars",
                "U+200B,U+200C",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    extract_data = json.loads(capsys.readouterr().out)
    assert extract_data["payload_bytes"] == len(b"flag{cli}")
    assert output.read_bytes() == b"flag{cli}"
