from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from oh_my_misc.cli import main
from oh_my_misc.zip_plaintext import (
    _MASK_2_32,
    _format_key,
    _keys_from_password,
    _keys_update,
    _NativeBkcrackAttack,
    _PlainZipEntry,
    _prepare_attack_data,
    _read_zip_cipher_target,
    _write_zip_entries,
    _zipcrypto_decrypt,
    known_plaintext_attack,
    known_plaintext_preset_attack,
    list_plaintext_presets,
    recover_password_from_keys,
    resolve_plaintext_preset,
)


def _key_hexes(password: str) -> tuple[str, str, str]:
    return tuple(_format_key(part) for part in _keys_from_password(password.encode("utf-8")))


def _encrypted_zip(path: Path, name: str = "hint.txt", data: bytes = b"known plaintext") -> None:
    _write_zip_entries(
        path,
        [_PlainZipEntry(name, data, (2024, 1, 2, 3, 4, 6), 0)],
        password="old",
    )


def _patch_native_attack(monkeypatch: pytest.MonkeyPatch, password: str = "old") -> None:
    import oh_my_misc.zip_plaintext as module

    monkeypatch.setattr(
        module,
        "_recover_keys_known_plaintext",
        lambda *args, **kwargs: _keys_from_password(password.encode("utf-8")),
    )


def _read_zip(path: Path, name: str, password: str | None = None) -> bytes:
    with zipfile.ZipFile(path) as archive:
        return archive.read(name, pwd=password.encode("utf-8") if password is not None else None)


def test_known_plaintext_attack_native_changes_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "flag.zip"
    plain = tmp_path / "hint.txt"
    out = tmp_path / "out.zip"
    payload = b"known plaintext"
    _encrypted_zip(archive, data=payload)
    plain.write_bytes(payload)
    _patch_native_attack(monkeypatch)

    result = known_plaintext_attack(
        archive,
        cipher_entry="hint.txt",
        plain_file=plain,
        output=out,
        new_password="123",
        bkcrack=tmp_path / "ignored-bkcrack",
    )

    assert result.tool_path == "native-python"
    assert result.keys == list(_key_hexes("old"))
    assert result.changed_password is True
    assert _read_zip(out, "hint.txt", "123") == payload
    assert result.command[0] == "native-bkcrack"
    assert "-U" in result.command


def test_keys_mode_decrypts_with_existing_keys(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    out = tmp_path / "clear.zip"
    payload = b"secret payload"
    _encrypted_zip(archive, data=payload)

    result = known_plaintext_attack(
        archive,
        keys=_key_hexes("old"),
        output=out,
        decrypt=True,
        bkcrack=tmp_path / "ignored-bkcrack",
    )

    assert result.decrypted is True
    assert _read_zip(out, "hint.txt") == payload
    assert "-D" in result.command


def test_recover_password_from_keys_native_bruteforce(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    _encrypted_zip(archive)

    result = recover_password_from_keys(
        archive,
        _key_hexes("az"),
        charset="?l",
        length="2",
        bkcrack=tmp_path / "ignored-bkcrack",
    )

    assert result.tool_path == "native-python"
    assert result.new_password == "az"
    assert "Password: az" in result.stdout
    assert "-b" in result.command


def test_native_attack_port_recovers_keys_from_matching_z_candidate(tmp_path: Path) -> None:
    archive = tmp_path / "flag.zip"
    payload = b"known plaintext payload 12345"
    _encrypted_zip(archive, data=payload)
    target = _read_zip_cipher_target(archive, "hint.txt")
    decrypted = _zipcrypto_decrypt(_keys_from_password(b"old"), target.ciphertext)
    keys = _keys_from_password(b"old")
    states = []
    for byte in decrypted[:12] + payload:
        states.append(keys)
        keys = _keys_update(keys, byte)
    data = _prepare_attack_data(target.ciphertext, target.check_byte, payload, 0, {})
    candidate = states[data.offset + 7][2] & _MASK_2_32

    attack = _NativeBkcrackAttack(data, 7)
    attack.carryout(candidate)

    assert attack.solutions[0] == _keys_from_password(b"old")


def test_zip_plaintext_cli_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "flag.zip"
    plain = tmp_path / "hint.txt"
    out = tmp_path / "out.zip"
    payload = b"known plaintext"
    _encrypted_zip(archive, data=payload)
    plain.write_bytes(payload)
    _patch_native_attack(monkeypatch)

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
                "--decrypt",
                "-o",
                str(out),
                "--json",
            ]
        )
        == 0
    )
    data = capsys.readouterr().out
    assert '"tool_path": "native-python"' in data
    assert '"keys"' in data
    assert _read_zip(out, "hint.txt") == payload


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


def test_known_plaintext_preset_attack_uses_native_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "flag.zip"
    out = tmp_path / "out.zip"
    _encrypted_zip(archive, name="flag.txt", data=b"flag{placeholder}")
    _patch_native_attack(monkeypatch)

    result = known_plaintext_preset_attack(
        archive,
        "text",
        cipher_entry="flag.txt",
        plain_text="lag{16e3",
        extra_text=["29:74f6"],
        output=out,
        new_password="new",
        bkcrack=tmp_path / "ignored-bkcrack",
    )

    assert result.preset == "text"
    assert result.generated_plaintext_hex == "6c61677b31366533"
    assert result.extra_plaintexts == ["29:37346636"]
    assert result.plain_source == "preset:text"
    assert result.keys == list(_key_hexes("old"))
    assert _read_zip(out, "flag.txt", "new") == b"flag{placeholder}"


def test_zip_plaintext_presets_cli_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert main(["zip", "plaintext", "presets", "--json"]) == 0
    out = capsys.readouterr().out
    assert '"count": 9' in out
    assert '"name": "png"' in out

    archive = tmp_path / "flag.zip"
    output = tmp_path / "out.zip"
    _encrypted_zip(archive, name="2.png", data=b"png placeholder")
    _patch_native_attack(monkeypatch)
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
                "--new-password",
                "new",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    data = capsys.readouterr().out
    assert '"preset": "png"' in data
    assert '"tool_path": "native-python"' in data
    assert _read_zip(output, "2.png", "new") == b"png placeholder"


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
def test_all_eight_presets_run_through_native_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    preset: str,
    kwargs: dict[str, object],
    expected_offset: int,
) -> None:
    archive = tmp_path / f"{preset}.zip"
    out = tmp_path / f"{preset}_out.zip"
    _encrypted_zip(archive, name="entry.bin", data=f"payload-{preset}".encode())
    _patch_native_attack(monkeypatch)

    result = known_plaintext_preset_attack(
        archive,
        preset,
        cipher_entry="entry.bin",
        output=out,
        new_password="new",
        bkcrack=tmp_path / "ignored-bkcrack",
        **kwargs,
    )

    assert result.preset == preset
    assert result.offset == expected_offset
    assert result.keys == list(_key_hexes("old"))
    assert _read_zip(out, "entry.bin", "new") == f"payload-{preset}".encode()


def test_custom_plain_file_and_custom_json_preset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "flag.zip"
    plain = tmp_path / "known.bin"
    out_file = tmp_path / "out_file.zip"
    out_json = tmp_path / "out_json.zip"
    preset_json = tmp_path / "pdf.json"
    _encrypted_zip(archive, name="mystery.bin", data=b"pdf placeholder")
    _patch_native_attack(monkeypatch)
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
        new_password="new",
        bkcrack=tmp_path / "ignored-bkcrack",
    )
    result_json = known_plaintext_preset_attack(
        archive,
        "custom",
        cipher_entry="mystery.bin",
        preset_file=preset_json,
        output=out_json,
        new_password="new",
        bkcrack=tmp_path / "ignored-bkcrack",
    )

    assert result_file.generated_plaintext_hex.startswith("255044462d312e37")
    assert result_json.preset == "pdf"
    assert result_json.generated_plaintext_hex == "255044462d312e37"
    assert result_json.extra_plaintexts == ["128:73747265616d"]
    assert _read_zip(out_file, "mystery.bin", "new") == b"pdf placeholder"
    assert _read_zip(out_json, "mystery.bin", "new") == b"pdf placeholder"
