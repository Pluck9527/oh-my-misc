from __future__ import annotations

import json
import stat
import sys
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


def test_snow_tool_backend_uses_stegsnow_flags(tmp_path: Path) -> None:
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "stego.txt"
    extracted = tmp_path / "out.bin"
    log = tmp_path / "args.jsonl"
    tool = tmp_path / "stegsnow"
    cover.write_text("visible\n", encoding="utf-8")
    script = f"""#!{sys.executable}
from __future__ import annotations
import json, shutil, sys
from pathlib import Path
log = Path({str(log)!r})
log.write_text((log.read_text() if log.exists() else '') + json.dumps(sys.argv[1:]) + '\\n')
args = sys.argv[1:]
if '-f' in args:
    infile = Path(args[-2]); outfile = Path(args[-1])
    outfile.write_bytes(infile.read_bytes() + b'\\t')
else:
    outfile = Path(args[-1])
    outfile.write_bytes(b'from-tool')
"""
    tool.write_text(script, encoding="utf-8")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

    hide_result = hide_snow(
        cover,
        stego,
        text="secret",
        password="pw",
        compress=True,
        backend="tool",
        snow_path=tool,
    )
    extract_result = extract_snow(
        stego,
        extracted,
        password="pw",
        compress=True,
        backend="tool",
        snow_path=tool,
    )

    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert hide_result.backend == "tool"
    assert extract_result.backend == "tool"
    assert calls[0][:5] == ["-Q", "-C", "-p", "pw", "-l"]
    assert "-f" in calls[0]
    assert calls[1] == ["-Q", "-C", "-p", "pw", str(stego), str(extracted)]
    assert extracted.read_bytes() == b"from-tool"
