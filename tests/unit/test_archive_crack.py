from __future__ import annotations

import binascii
import json
import struct
from pathlib import Path

import py7zr

from oh_my_misc.archive_crack import crack_archive_password, zipcrypto_encrypt_for_test
from oh_my_misc.cli import main


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
        + struct.pack("<HHHHHIIIHH", 20, 0x01, 0, dostime, dosdate, crc, csize, usize, len(name_b), 0)
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


def test_crack_zipcrypto_wordlist_and_extract(tmp_path: Path) -> None:
    archive = tmp_path / "secret.zip"
    wordlist = tmp_path / "passwords.txt"
    output = tmp_path / "out"
    _make_zipcrypto_store(archive, "flag.txt", b"flag{archive_crack}", b"secret")
    wordlist.write_text("123456\nsecret\npassword\n", encoding="utf-8")

    result = crack_archive_password(
        archive, output, wordlist=wordlist, workers=1, chunk_size=2, backend="native"
    )

    assert result.operation == "zip.crack"
    assert result.backend == "native-zipcrypto"
    assert result.found_password == "secret"
    assert result.verified is True
    assert result.attempts == 2
    assert (output / "flag.txt").read_bytes() == b"flag{archive_crack}"


def test_crack_zipcrypto_generated_digits(tmp_path: Path) -> None:
    archive = tmp_path / "pin.zip"
    _make_zipcrypto_store(archive, "pin.txt", b"ok", b"42")

    result = crack_archive_password(
        archive,
        charset="digits",
        min_length=1,
        max_length=2,
        workers=1,
        chunk_size=16,
        backend="native",
    )

    assert result.found_password == "42"
    assert result.verified is True


def test_crack_7z_native_wordlist_and_extract(tmp_path: Path) -> None:
    archive = tmp_path / "secret.7z"
    payload = tmp_path / "flag.txt"
    wordlist = tmp_path / "passwords.txt"
    output = tmp_path / "out"
    payload.write_bytes(b"flag{native_7z_crack}")
    with py7zr.SevenZipFile(archive, mode="w", password="secret") as seven_zip:
        seven_zip.write(payload, arcname="flag.txt")
    payload.unlink()
    wordlist.write_text("bad\nsecret\n", encoding="utf-8")

    result = crack_archive_password(
        archive,
        output,
        wordlist=wordlist,
        workers=1,
        chunk_size=1,
        backend="auto",
        sevenzip=tmp_path / "ignored-external-7z",
    )

    assert result.operation == "archive.crack"
    assert result.backend == "native-7z"
    assert result.archive_format == "7z"
    assert result.found_password == "secret"
    assert result.attempts == 2
    assert result.verified is True
    assert (output / "flag.txt").read_bytes() == b"flag{native_7z_crack}"


def test_zip_crack_cli_json(tmp_path: Path, capsys) -> None:
    archive = tmp_path / "secret.zip"
    wordlist = tmp_path / "passwords.txt"
    output = tmp_path / "out"
    _make_zipcrypto_store(archive, "flag.txt", b"FLAG", b"secret")
    wordlist.write_text("bad\nsecret\n", encoding="utf-8")

    assert (
        main(
            [
                "zip",
                "crack",
                str(archive),
                "--wordlist",
                str(wordlist),
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
    assert data["found_password"] == "secret"
    assert data["verified"] is True
    assert (output / "flag.txt").read_bytes() == b"FLAG"
