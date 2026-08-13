from __future__ import annotations

import binascii
import json
import zipfile
from pathlib import Path

import pytest

from oh_my_misc.cli import main
from oh_my_misc.zip_crc import brute_zip_crc, list_zip_crc, reverse_crc32_direct


def _make_zip(path: Path, name: str, data: bytes) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)


def test_reverse_crc32_direct_printable_recovers_flag() -> None:
    crc = binascii.crc32(b"flag") & 0xFFFFFFFF

    result = reverse_crc32_direct(crc, 4, charset="printable")

    assert result.candidates == 1
    assert result.candidate_text == ["flag"]
    assert result.candidate_hex == [b"flag".hex()]


def test_brute_zip_crc_single_entry_writes_output(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    output = tmp_path / "recovered.bin"
    _make_zip(archive, "tiny.txt", b"flag")

    result = brute_zip_crc(archive, output, charset="printable")

    assert result.operation == "zip.crc.brute"
    assert result.entry == "tiny.txt"
    assert result.candidates == 1
    assert output.read_bytes() == b"flag"


def test_zip_crc_list_reports_entries(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    _make_zip(archive, "a.txt", b"abc")

    result = list_zip_crc(archive)

    assert result.count == 1
    assert result.entries is not None
    assert result.entries[0]["filename"] == "a.txt"
    assert result.entries[0]["crc32"] == f"0x{binascii.crc32(b'abc') & 0xFFFFFFFF:08x}"


def test_brute_zip_crc_requires_entry_for_multi_file(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", b"aa")
        zf.writestr("b.txt", b"bb")

    with pytest.raises(ValueError, match="--entry"):
        brute_zip_crc(archive, charset="printable")


def test_crc_with_prefix_and_suffix_constraints() -> None:
    payload = b"flag{crc}"
    crc = binascii.crc32(payload) & 0xFFFFFFFF

    result = reverse_crc32_direct(
        crc,
        len(payload),
        charset="flag",
        prefix="flag{",
        suffix="}",
    )

    assert payload.hex() in result.candidate_hex
    assert "flag{crc}" in result.candidate_text


def test_zip_crc_cli_json_roundtrip(tmp_path: Path, capsys) -> None:
    archive = tmp_path / "sample.zip"
    output = tmp_path / "out.bin"
    _make_zip(archive, "tiny.txt", b"OK42")

    assert main(["zip", "crc", "list", str(archive), "--json"]) == 0
    list_data = json.loads(capsys.readouterr().out)
    assert list_data["entries"][0]["file_size"] == 4

    assert (
        main(
            [
                "zip",
                "crc",
                "brute",
                str(archive),
                "--charset",
                "printable",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    brute_data = json.loads(capsys.readouterr().out)
    assert brute_data["candidate_text"] == ["OK42"]
    assert output.read_bytes() == b"OK42"
