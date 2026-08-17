from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from oh_my_misc.cli import main
from oh_my_misc.oursecret import (
    OURSECRET_EOF_SIGNATURE,
    check_trailer,
    extract_oursecret,
    hide_oursecret,
    inspect_oursecret,
    password_tag,
)


def _bmp24(path: Path, *, width: int = 180, height: int = 160) -> None:
    row_bytes = ((width * 3 + 3) // 4) * 4
    pixel_bytes = row_bytes * height
    header = bytearray(54)
    header[:2] = b"BM"
    struct.pack_into("<I", header, 2, 54 + pixel_bytes)
    struct.pack_into("<I", header, 10, 54)
    struct.pack_into("<I", header, 14, 40)
    struct.pack_into("<i", header, 18, width)
    struct.pack_into("<i", header, 22, height)
    struct.pack_into("<H", header, 26, 1)
    struct.pack_into("<H", header, 28, 24)
    struct.pack_into("<I", header, 34, pixel_bytes)
    path.write_bytes(bytes(header) + bytes([0xAA]) * pixel_bytes)


def test_oursecret_append_roundtrip(tmp_path: Path) -> None:
    carrier = tmp_path / "carrier.bin"
    payload = tmp_path / "secret.txt"
    stego = tmp_path / "stego.bin"
    out_dir = tmp_path / "out"
    carrier.write_bytes(b"carrier-data\n")
    payload.write_text("flag{oursecret}\n", encoding="utf-8")

    hide_result = hide_oursecret(
        carrier,
        stego,
        payload_paths=[payload],
        password="pass123",
        mode="append",
    )
    trailer_info = check_trailer(stego.read_bytes()[-28:])
    assert trailer_info is not None
    assert trailer_info[1] == password_tag("pass123")
    assert hide_result.data_size == trailer_info[0]
    assert (
        stego.read_bytes()[len(b"carrier-data\n") : len(b"carrier-data\n") + 40]
        == OURSECRET_EOF_SIGNATURE
    )
    assert hide_result.signature_offset == len(b"carrier-data\n")

    inspect_result = inspect_oursecret(stego)
    extract_result = extract_oursecret(stego, out_dir, password="pass123")

    assert inspect_result.mode == "append"
    assert inspect_result.signature_offset == len(b"carrier-data\n")
    assert extract_result.password_verified is True
    assert (out_dir / "secret.txt").read_text(encoding="utf-8") == "flag{oursecret}\n"


def test_oursecret_extract_without_password_uses_fixed_cipher_key(tmp_path: Path) -> None:
    carrier = tmp_path / "carrier.bin"
    payload = tmp_path / "secret.txt"
    stego = tmp_path / "stego.bin"
    out_dir = tmp_path / "out"
    carrier.write_bytes(b"carrier")
    payload.write_bytes(b"open-without-password")
    hide_oursecret(carrier, stego, payload_paths=[payload], password="real-password")

    result = extract_oursecret(stego, out_dir)

    assert result.password_verified is None
    assert (out_dir / "secret.txt").read_bytes() == b"open-without-password"


def test_oursecret_append_legacy_no_signature_still_extracts(tmp_path: Path) -> None:
    carrier = tmp_path / "carrier.bin"
    payload = tmp_path / "secret.txt"
    stego = tmp_path / "legacy.bin"
    out_dir = tmp_path / "out"
    carrier.write_bytes(b"legacy-carrier")
    payload.write_bytes(b"legacy")

    hide_result = hide_oursecret(
        carrier,
        stego,
        payload_paths=[payload],
        password="",
        signature=False,
    )
    inspect_result = inspect_oursecret(stego)
    extract_result = extract_oursecret(stego, out_dir)

    assert hide_result.signature_offset is None
    assert inspect_result.signature_offset is None
    assert extract_result.password_verified is None
    assert (out_dir / "secret.txt").read_bytes() == b"legacy"


def test_oursecret_signature_only_scan(tmp_path: Path) -> None:
    carrier = tmp_path / "signature-only.bin"
    carrier.write_bytes(b"raw-carrier" + OURSECRET_EOF_SIGNATURE + b"opaque")

    result = inspect_oursecret(carrier)

    assert result.mode == "signature"
    assert result.count == 1
    assert result.signature_offset == len(b"raw-carrier")
    assert result.entries[0]["kind"] == "oursecret-eof-signature"


def test_oursecret_cli_signature_only_inspect(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    carrier = tmp_path / "signature-only.bin"
    carrier.write_bytes(b"raw-carrier" + OURSECRET_EOF_SIGNATURE + b"opaque")

    assert main(["stego", "oursecret", "inspect", str(carrier), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["mode"] == "signature"
    assert payload["signature_offset"] == len(b"raw-carrier")


def test_oursecret_wrong_password_rejected(tmp_path: Path) -> None:
    carrier = tmp_path / "carrier.bin"
    payload = tmp_path / "secret.txt"
    stego = tmp_path / "stego.bin"
    carrier.write_bytes(b"carrier")
    payload.write_bytes(b"secret")
    hide_oursecret(carrier, stego, payload_paths=[payload], password="right")

    with pytest.raises(ValueError, match="password tag"):
        extract_oursecret(stego, tmp_path / "out", password="wrong")


def test_oursecret_lsb_bmp_roundtrip(tmp_path: Path) -> None:
    carrier = tmp_path / "carrier.bmp"
    payload = tmp_path / "message.bin"
    stego = tmp_path / "stego.bmp"
    out_dir = tmp_path / "out"
    _bmp24(carrier)
    payload.write_bytes(b"bmp-lsb-payload")

    hide_result = hide_oursecret(
        carrier,
        stego,
        payload_paths=[payload],
        password="pw",
        mode="lsb",
    )
    extract_result = extract_oursecret(stego, out_dir, password="pw", mode="lsb")

    assert hide_result.mode == "lsb"
    assert extract_result.mode == "lsb"
    assert (out_dir / "message.bin").read_bytes() == b"bmp-lsb-payload"


def test_oursecret_cli_json_roundtrip(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    carrier = tmp_path / "carrier.bin"
    payload = tmp_path / "secret.txt"
    stego = tmp_path / "stego.bin"
    out_dir = tmp_path / "out"
    carrier.write_bytes(b"carrier")
    payload.write_text("cli-roundtrip", encoding="utf-8")

    assert (
        main(
            [
                "stego",
                "oursecret",
                "hide",
                str(carrier),
                "--payload",
                str(payload),
                "--password",
                "pw",
                "-o",
                str(stego),
                "--json",
            ]
        )
        == 0
    )
    hidden = json.loads(capsys.readouterr().out)
    assert hidden["operation"] == "stego.oursecret.hide"

    assert (
        main(
            [
                "stego",
                "oursecret",
                "extract",
                str(stego),
                "--password",
                "pw",
                "-o",
                str(out_dir),
                "--json",
            ]
        )
        == 0
    )
    extracted = json.loads(capsys.readouterr().out)
    assert extracted["operation"] == "stego.oursecret.extract"
    assert (out_dir / "secret.txt").read_text(encoding="utf-8") == "cli-roundtrip"
