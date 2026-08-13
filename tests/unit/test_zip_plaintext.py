from __future__ import annotations

from pathlib import Path

import pytest

from oh_my_misc.cli import main
from oh_my_misc.zip_plaintext import (
    known_plaintext_attack,
    known_plaintext_preset_attack,
    list_plaintext_presets,
    recover_password_from_keys,
    resolve_plaintext_preset,
)


def _fake_bkcrack(path: Path) -> Path:
    script = path / "bkcrack"
    script.write_text(
        """#!/usr/bin/env python3
from __future__ import annotations
import pathlib, sys
args = sys.argv[1:]
print('bkcrack 1.8.1 - fake')
if '-b' in args or '-m' in args:
    print('Password: secret')
elif '-D' in args:
    out = pathlib.Path(args[args.index('-D') + 1]); out.write_bytes(b'CLEARZIP')
    print('Wrote decrypted archive')
elif '-U' in args:
    out = pathlib.Path(args[args.index('-U') + 1]); out.write_bytes(b'NEWZIP')
    print('Wrote changed password archive')
else:
    print('Keys: afb9fee3 f8795353 f6de1d4e')
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _minimal_zip(path: Path) -> None:
    import zipfile

    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("hint.txt", b"known plaintext")


def test_known_plaintext_attack_parses_keys_and_changes_password(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    plain = tmp_path / "hint.txt"
    out = tmp_path / "out.zip"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)
    plain.write_bytes(b"known plaintext")

    result = known_plaintext_attack(
        archive,
        cipher_entry="hint.txt",
        plain_file=plain,
        output=out,
        new_password="123",
        bkcrack=tool,
    )

    assert result.keys == ["afb9fee3", "f8795353", "f6de1d4e"]
    assert result.changed_password is True
    assert out.read_bytes() == b"NEWZIP"
    assert "-U" in result.command


def test_keys_mode_decrypts_with_existing_keys(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    out = tmp_path / "clear.zip"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)

    result = known_plaintext_attack(
        archive,
        keys=("afb9fee3", "f8795353", "f6de1d4e"),
        output=out,
        decrypt=True,
        bkcrack=tool,
    )

    assert result.decrypted is True
    assert out.read_bytes() == b"CLEARZIP"
    assert "-D" in result.command


def test_recover_password_from_keys_parses_password(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)

    result = recover_password_from_keys(
        archive,
        ("afb9fee3", "f8795353", "f6de1d4e"),
        length="1..6",
        bkcrack=tool,
    )

    assert result.new_password == "secret"
    assert "-b" in result.command


def test_zip_plaintext_cli_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    archive = tmp_path / "flag.zip"
    plain = tmp_path / "hint.txt"
    out = tmp_path / "out.zip"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)
    plain.write_bytes(b"known plaintext")

    assert (
        main(
            [
                "zip",
                "plaintext",
                "attack",
                str(archive),
                "--entry",
                "hint.txt",
                "--plain-file",
                str(plain),
                "--bkcrack",
                str(tool),
                "-o",
                str(out),
                "--json",
            ]
        )
        == 0
    )
    assert '"keys"' in capsys.readouterr().out


def test_plaintext_presets_list_contains_eight_classic_cases_and_custom() -> None:
    result = list_plaintext_presets()

    assert result.count == 9
    names = [item["name"] for item in result.presets]
    assert names[:8] == [
        "text",
        "png",
        "zip",
        "exe",
        "pcapng",
        "xml",
        "svg",
        "vmdk",
    ]
    assert names[8] == "custom"
    assert result.presets[1]["plain_hex"] == "89504e470d0a1a0a0000000d49484452"


def test_resolve_zip_and_text_presets_generate_offsets_and_extra() -> None:
    zip_preset = resolve_plaintext_preset("zip", inner_name="secret.bin")
    text_preset = resolve_plaintext_preset("text", plain_text="lag{16e3", extra_text=["29:74f6"])

    assert zip_preset.offset == 30
    assert zip_preset.plain_bytes == b"secret.bin"
    assert "0:504b0304" in zip_preset.extra
    assert text_preset.plain_bytes == b"lag{16e3"
    assert "29:37346636" in text_preset.extra


def test_known_plaintext_preset_attack_builds_bkcrack_command(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    out = tmp_path / "out.zip"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)

    result = known_plaintext_preset_attack(
        archive,
        "text",
        cipher_entry="flag.txt",
        plain_text="lag{16e3",
        extra_text=["29:74f6"],
        output=out,
        bkcrack=tool,
    )

    assert result.preset == "text"
    assert result.generated_plaintext_hex == "6c61677b31366533"
    assert result.extra_plaintexts == ["29:37346636"]
    assert result.plain_source == "preset:text"
    assert result.keys == ["afb9fee3", "f8795353", "f6de1d4e"]
    assert out.read_bytes() == b"NEWZIP"


def test_zip_plaintext_presets_cli_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["zip", "plaintext", "presets", "--json"]) == 0
    out = capsys.readouterr().out
    assert '"count": 9' in out
    assert '"name": "png"' in out

    archive = tmp_path / "flag.zip"
    output = tmp_path / "out.zip"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)
    assert (
        main(
            [
                "zip",
                "plaintext",
                "preset",
                "png",
                str(archive),
                "--entry",
                "2.png",
                "--bkcrack",
                str(tool),
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    data = capsys.readouterr().out
    assert '"preset": "png"' in data
    assert output.read_bytes() == b"NEWZIP"


@pytest.mark.parametrize(
    ("preset", "kwargs", "expected_offset"),
    [
        ("text", {"plain_text": "lag{16e3", "extra_text": ["29:74f6"]}, 0),
        ("png", {}, 0),
        ("zip", {"inner_name": "flag.txt"}, 30),
        ("exe", {}, 64),
        ("pcapng", {}, 6),
        ("xml", {}, 0),
        ("svg", {}, 0),
        ("vmdk", {}, 0),
    ],
)
def test_all_eight_presets_run_through_fake_bkcrack(
    tmp_path: Path, preset: str, kwargs: dict[str, object], expected_offset: int
) -> None:
    archive = tmp_path / f"{preset}.zip"
    out = tmp_path / f"{preset}_out.zip"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)

    result = known_plaintext_preset_attack(
        archive,
        preset,
        cipher_entry="entry.bin",
        output=out,
        bkcrack=tool,
        **kwargs,
    )

    assert result.preset == preset
    assert result.offset == expected_offset
    assert result.keys == ["afb9fee3", "f8795353", "f6de1d4e"]
    assert out.read_bytes() == b"NEWZIP"


def test_custom_plain_file_and_custom_json_preset(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    plain = tmp_path / "known.bin"
    out_file = tmp_path / "out_file.zip"
    out_json = tmp_path / "out_json.zip"
    preset_json = tmp_path / "pdf.json"
    tool = _fake_bkcrack(tmp_path)
    _minimal_zip(archive)
    plain.write_bytes(b"%PDF-1.7 custom known bytes")
    preset_json.write_text(
        '{"name":"pdf","offset":0,"plain_hex":"255044462d312e37","extra_text":["128:stream"]}',
        encoding="utf-8",
    )

    result_file = known_plaintext_preset_attack(
        archive,
        "custom",
        cipher_entry="mystery.bin",
        plain_file=plain,
        output=out_file,
        bkcrack=tool,
    )
    result_json = known_plaintext_preset_attack(
        archive,
        "custom",
        cipher_entry="mystery.bin",
        preset_file=preset_json,
        output=out_json,
        bkcrack=tool,
    )

    assert result_file.generated_plaintext_hex.startswith("255044462d312e37")
    assert result_json.preset == "pdf"
    assert result_json.generated_plaintext_hex == "255044462d312e37"
    assert result_json.extra_plaintexts == ["128:73747265616d"]
    assert out_file.read_bytes() == b"NEWZIP"
    assert out_json.read_bytes() == b"NEWZIP"
