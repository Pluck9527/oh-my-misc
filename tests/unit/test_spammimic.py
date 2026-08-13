from __future__ import annotations

import json
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.spammimic import (
    brute_spammimic,
    decode_spammimic,
    encode_spammimic,
)


def test_spammimic_native_spam_roundtrip(tmp_path: Path) -> None:
    stego = tmp_path / "spam.txt"
    output = tmp_path / "out.bin"

    encode_result = encode_spammimic(stego, text="flag{spam_mimic}", mode="spam")
    decode_result = decode_spammimic(stego, output, mode="spam", backend="native")

    assert encode_result.backend == "native"
    assert "Senate bill" in stego.read_text(encoding="utf-8")
    assert decode_result.payload_bytes == len(b"flag{spam_mimic}")
    assert output.read_bytes() == b"flag{spam_mimic}"


def test_spammimic_native_space_roundtrip(tmp_path: Path) -> None:
    cover = tmp_path / "cover.txt"
    stego = tmp_path / "space.txt"
    output = tmp_path / "out.bin"
    cover.write_text("alpha\nbeta\n", encoding="utf-8")

    encode_spammimic(stego, text="flag{space_mimic}", mode="space", cover_path=cover)
    decode_spammimic(stego, output, mode="space", backend="native")

    assert b"\t" in stego.read_bytes()
    assert output.read_bytes() == b"flag{space_mimic}"


def test_spammimic_native_password_and_wordlist(tmp_path: Path) -> None:
    stego = tmp_path / "spam-password.txt"
    output = tmp_path / "out.bin"
    brute_output = tmp_path / "brute.bin"
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("guess\nswordfish\n", encoding="utf-8")

    encode_spammimic(stego, text="flag{spam_password}", mode="spam", password="swordfish")
    result = decode_spammimic(stego, output, mode="spam", backend="native", password="swordfish")
    brute_result = brute_spammimic(
        stego,
        wordlist,
        brute_output,
        mode="spam",
        backend="native",
        contains=b"flag{",
        include_default=False,
    )

    assert result.password_verified
    assert output.read_bytes() == b"flag{spam_password}"
    assert brute_result.found_password == "swordfish"
    assert brute_result.attempts == 2
    assert brute_output.read_bytes() == b"flag{spam_password}"


def test_spammimic_cli_json_roundtrip(tmp_path: Path, capsys) -> None:
    stego = tmp_path / "spam.txt"
    output = tmp_path / "out.bin"

    assert (
        main(
            [
                "text",
                "spammimic",
                "encode",
                "--text",
                "flag{cli_spam}",
                "-o",
                str(stego),
                "--json",
            ]
        )
        == 0
    )
    encode_data = json.loads(capsys.readouterr().out)
    assert encode_data["operation"] == "text.spammimic.encode"
    assert encode_data["mode"] == "spam"

    assert (
        main(
            [
                "text",
                "spammimic",
                "decode",
                str(stego),
                "-o",
                str(output),
                "--backend",
                "native",
                "--json",
            ]
        )
        == 0
    )
    decode_data = json.loads(capsys.readouterr().out)
    assert decode_data["operation"] == "text.spammimic.decode"
    assert output.read_bytes() == b"flag{cli_spam}"


def test_spammimic_remote_parsers(monkeypatch, tmp_path: Path) -> None:
    import oh_my_misc.spammimic as sm

    responses: list[tuple[str, dict[str, str]]] = []

    def fake_post(url: str, values: dict[str, str]) -> str:
        responses.append((url, values))
        if "encode" in url:
            return '<textarea name=cyphertext>Dear Remote &amp; Test</textarea>'
        return '<input type=text name=plaintext value="flag{remote}">'

    monkeypatch.setattr(sm, "_post_form", fake_post)
    stego = tmp_path / "remote.txt"
    out = tmp_path / "remote.bin"

    encode_spammimic(stego, text="flag{remote}", backend="remote", password="pw")
    decode_spammimic(stego, out, backend="remote", password="pw")

    assert stego.read_text(encoding="utf-8") == "Dear Remote & Test"
    assert out.read_bytes() == b"flag{remote}"
    assert responses[0][1]["password"] == "pw"
    assert responses[1][1]["password"] == "pw"
