from __future__ import annotations

import base64
import binascii
import json
import struct
from pathlib import Path

from oh_my_misc.archive_crack import zipcrypto_encrypt_for_test
from oh_my_misc.cli import main
from oh_my_misc.zip_invisible import crack_invisible_archive_password, invisible_password_candidates


def _make_zipcrypto_store(path: Path, name: str, data: bytes, password: bytes) -> None:
    crc = binascii.crc32(data) & 0xFFFFFFFF
    dostime = 0x4A21
    dosdate = 0x5B4D
    name_b = name.encode("utf-8")
    encrypted = zipcrypto_encrypt_for_test(password, data, (crc >> 24) & 0xFF)
    csize = len(encrypted)
    usize = len(data)
    local = (
        b"PK\x03\x04"
        + struct.pack(
            "<HHHHHIIIHH", 20, 0x01, 0, dostime, dosdate, crc, csize, usize, len(name_b), 0
        )
        + name_b
        + encrypted
    )
    central_offset = len(local)
    central = (
        b"PK\x01\x02"
        + struct.pack(
            "<HHHHHHIIIHHHHHII",
            20,
            20,
            0x01,
            0,
            dostime,
            dosdate,
            crc,
            csize,
            usize,
            len(name_b),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name_b
    )
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), central_offset, 0)
    path.write_bytes(local + central + eocd)


def test_invisible_candidates_from_base64_and_raw() -> None:
    candidates = list(
        invisible_password_candidates(
            password_b64=[base64.b64encode(b"\x00\xff").decode("ascii")],
            b64_file=None,
            password_text=[],
            text_file=None,
            brute_raw=True,
            min_bytes=1,
            max_bytes=1,
            zero_width=False,
            min_chars=1,
            max_chars=1,
            zero_width_chars="\u200b",
            encoding="utf-8",
        )
    )

    assert candidates[0] == b"\x00\xff"
    assert b"\x00" in candidates
    assert b"\xff" in candidates


def test_crack_invisible_zipcrypto_base64_password(tmp_path: Path) -> None:
    archive = tmp_path / "secret.zip"
    output = tmp_path / "out"
    password = b"\x00\xff"
    _make_zipcrypto_store(archive, "flag.txt", b"flag{invisible}", password)

    result = crack_invisible_archive_password(
        archive,
        output,
        password_b64=[base64.b64encode(password).decode("ascii")],
        backend="native",
        workers=1,
    )

    assert result.operation == "zip.invisible-password"
    assert result.found_password_hex == "00ff"
    assert result.verified is True
    assert (output / "flag.txt").read_bytes() == b"flag{invisible}"


def test_crack_invisible_zipcrypto_raw_bruteforce(tmp_path: Path) -> None:
    archive = tmp_path / "raw.zip"
    _make_zipcrypto_store(archive, "flag.txt", b"ok", b"\x00")

    result = crack_invisible_archive_password(
        archive,
        brute_raw=True,
        min_bytes=1,
        max_bytes=1,
        backend="native",
        workers=1,
        chunk_size=64,
    )

    assert result.found_password_hex == "00"
    assert result.attempts == 1


def test_crack_zero_width_password(tmp_path: Path) -> None:
    archive = tmp_path / "zw.zip"
    password_text = "\u200b"
    _make_zipcrypto_store(archive, "flag.txt", b"zw", password_text.encode("utf-8"))

    result = crack_invisible_archive_password(
        archive,
        zero_width=True,
        min_chars=1,
        max_chars=1,
        zero_width_chars=password_text,
        backend="native",
        workers=1,
    )

    assert result.found_password == password_text
    assert result.found_password_hex == password_text.encode("utf-8").hex()


def test_zip_invisible_cli_json(tmp_path: Path, capsys) -> None:
    archive = tmp_path / "secret.zip"
    output = tmp_path / "out"
    password = b"\x00\x01"
    _make_zipcrypto_store(archive, "flag.txt", b"FLAG", password)

    assert (
        main(
            [
                "zip",
                "invisible-password",
                str(archive),
                "--password-b64",
                base64.b64encode(password).decode("ascii"),
                "--backend",
                "native",
                "--workers",
                "1",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "zip.invisible-password"
    assert data["found_password_hex"] == "0001"
    assert (output / "flag.txt").read_bytes() == b"FLAG"
