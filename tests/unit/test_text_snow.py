from __future__ import annotations

import json
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.text_snow import capacity_snow, extract_snow, hide_snow


def _strip_trailing_ws(data: bytes) -> bytes:
    return b"\n".join(line.rstrip(b" \t\r") for line in data.splitlines()) + b"\n"


def test_snow_native_roundtrip_keeps_visible_cover(tmp_path: Path) -> None:
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "stego.txt"
    extracted = tmp_path / "flag.bin"
    cover.write_bytes(b"alpha\nbeta\ngamma\n")

    result = hide_snow(cover, stego, text="flag{snow}", backend="native")
    extract_result = extract_snow(stego, extracted, backend="native")

    assert result.backend == "native"
    assert result.payload_bytes == len(b"flag{snow}")
    assert b"\t" in stego.read_bytes()
    assert _strip_trailing_ws(stego.read_bytes()) == cover.read_bytes()
    assert extract_result.payload_bytes == len(b"flag{snow}")
    assert extracted.read_bytes() == b"flag{snow}"


def test_snow_capacity_reports_range(tmp_path: Path) -> None:
    cover = tmp_path / "cover.txt"
    cover.write_text("short\nline\n", encoding="utf-8")

    result = capacity_snow(cover, line_length=80)

    assert result.operation == "text.snow.capacity"
    assert result.capacity_bits_low > 0
    assert result.capacity_bits_high >= result.capacity_bits_low


def test_snow_cli_json_roundtrip(tmp_path: Path, capsys) -> None:
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "stego.txt"
    extracted = tmp_path / "out.bin"
    cover.write_text("one\ntwo\nthree\n", encoding="utf-8")

    assert (
        main(
            ["text", "snow", "hide", str(cover), "--text", "flag{cli}", "-o", str(stego), "--json"]
        )
        == 0
    )
    hide_data = json.loads(capsys.readouterr().out)
    assert hide_data["operation"] == "text.snow.hide-native"
    assert hide_data["backend"] == "native"

    assert main(["text", "snow", "extract", str(stego), "-o", str(extracted), "--json"]) == 0
    extract_data = json.loads(capsys.readouterr().out)
    assert extract_data["operation"] == "text.snow.extract-native"
    assert extracted.read_bytes() == b"flag{cli}"


def test_snow_password_compress_tool_alias_is_native(tmp_path: Path) -> None:
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "stego.txt"
    extracted = tmp_path / "out.bin"
    ignored_tool = tmp_path / "missing-stegsnow"
    cover.write_text("visible\ncarrier\nlines\n", encoding="utf-8")

    hide_result = hide_snow(
        cover,
        stego,
        text="secret-native",
        password="pw",
        compress=True,
        backend="tool",
        snow_path=ignored_tool,
    )
    extract_result = extract_snow(
        stego,
        extracted,
        password="pw",
        compress=True,
        backend="tool",
        snow_path=ignored_tool,
    )

    assert hide_result.backend == "native"
    assert hide_result.tool_path == "python"
    assert extract_result.backend == "native"
    assert extract_result.tool_path == "python"
    assert extracted.read_bytes() == b"secret-native"
