from __future__ import annotations

import json
from pathlib import Path

import pytest

from oh_my_misc.cli import main
from oh_my_misc.text_cloakify import (
    CLOAKIFY_ALPHABET,
    cloakify_file,
    decloakify_file,
    inspect_cloakify,
)


def _write_cipher(path: Path, prefix: str = "token") -> None:
    path.write_text(
        "".join(f"{prefix}-{index:02d}\n" for index, _ in enumerate(CLOAKIFY_ALPHABET)),
        encoding="utf-8",
    )


def test_cloakify_native_roundtrip(tmp_path: Path) -> None:
    payload = tmp_path / "payload.bin"
    cipher = tmp_path / "passwd.txt"
    cloaked = tmp_path / "cipher.txt"
    output = tmp_path / "out.bin"
    payload.write_bytes(b"flag{cloakify}\x00zip")
    _write_cipher(cipher)

    cloak = cloakify_file(payload, cipher, cloaked)
    decloak = decloakify_file(cloaked, cipher, output)

    assert cloak.alphabet_size == 65
    assert cloak.cloaked_lines == cloak.base64_chars
    assert decloak.payload_bytes == len(b"flag{cloakify}\x00zip")
    assert output.read_bytes() == b"flag{cloakify}\x00zip"


def test_decloakify_accepts_missing_final_newline(tmp_path: Path) -> None:
    payload = tmp_path / "payload.txt"
    cipher = tmp_path / "cipher.txt"
    cloaked = tmp_path / "cloaked.txt"
    output = tmp_path / "out.txt"
    payload.write_text("hello", encoding="utf-8")
    _write_cipher(cipher, prefix="单词")
    cloakify_file(payload, cipher, cloaked)
    cloaked.write_text(cloaked.read_text(encoding="utf-8").rstrip("\n"), encoding="utf-8")

    decloakify_file(cloaked, cipher, output)

    assert output.read_text(encoding="utf-8") == "hello"


def test_inspect_reports_unknown_lines(tmp_path: Path) -> None:
    cipher = tmp_path / "cipher.txt"
    cloaked = tmp_path / "cloaked.txt"
    _write_cipher(cipher)
    cloaked.write_text("token-00\nunknown\ntoken-01\n", encoding="utf-8")

    result = inspect_cloakify(cloaked, cipher)

    assert result.cloaked_lines == 3
    assert result.known_lines == 2
    assert result.unknown_lines == 1


def test_decloakify_rejects_unknown_by_default(tmp_path: Path) -> None:
    cipher = tmp_path / "cipher.txt"
    cloaked = tmp_path / "cloaked.txt"
    output = tmp_path / "out.bin"
    _write_cipher(cipher)
    cloaked.write_text("token-00\nunknown\n", encoding="utf-8")

    with pytest.raises(ValueError, match="找不到"):
        decloakify_file(cloaked, cipher, output)


def test_cli_cloakify_json_roundtrip(tmp_path: Path, capsys) -> None:
    payload = tmp_path / "payload.bin"
    cipher = tmp_path / "passwd.txt"
    cloaked = tmp_path / "cipher.txt"
    output = tmp_path / "out.bin"
    payload.write_bytes(b"flag{cli-cloakify}")
    _write_cipher(cipher)

    assert (
        main(
            [
                "text",
                "cloakify",
                "cloak",
                str(payload),
                "--cipher",
                str(cipher),
                "-o",
                str(cloaked),
                "--json",
            ]
        )
        == 0
    )
    cloak_data = json.loads(capsys.readouterr().out)
    assert cloak_data["operation"] == "text.cloakify.cloak"
    assert cloak_data["alphabet_size"] == 65

    assert (
        main(
            [
                "text",
                "cloak",
                "decloak",
                str(cloaked),
                "--cipher",
                str(cipher),
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    decloak_data = json.loads(capsys.readouterr().out)
    assert decloak_data["operation"] == "text.cloakify.decloak"
    assert output.read_bytes() == b"flag{cli-cloakify}"
