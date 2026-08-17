from __future__ import annotations

import json
import zlib
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.rar_ntfs import extract_rar_ntfs_streams, list_rar_ntfs_streams

RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"
RAR4_LONG_BLOCK = 0x8000
RAR4_LHD_SOLID = 0x0010
RAR4_HEAD_MAIN = 0x73
RAR4_HEAD_FILE = 0x74
RAR4_HEAD_SERVICE = 0x7A
RAR4_HEAD_ENDARC = 0x7B


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _extra(record_type: int, payload: bytes) -> bytes:
    body = _vint(record_type) + payload
    return _vint(len(body)) + body


def _block(
    header_type: int, flags: int, body: bytes = b"", extra: bytes = b"", data: bytes = b""
) -> bytes:
    actual_flags = flags
    if extra:
        actual_flags |= 0x0001
    if data:
        actual_flags |= 0x0002
    header_data = _vint(header_type) + _vint(actual_flags)
    if extra:
        header_data += _vint(len(extra))
    if data:
        header_data += _vint(len(data))
    header_data += body + extra
    size = _vint(len(header_data))
    crc = zlib.crc32(size + header_data) & 0xFFFFFFFF
    return crc.to_bytes(4, "little") + size + header_data + data


def _file_body(name: str, data: bytes) -> bytes:
    name_bytes = name.encode()
    file_flags = 0x0004
    comp_info = 0
    host_os = 0
    return b"".join(
        (
            _vint(file_flags),
            _vint(len(data)),
            _vint(0x20),
            (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "little"),
            _vint(comp_info),
            _vint(host_os),
            _vint(len(name_bytes)),
            name_bytes,
        )
    )


def _sample_rar(path: Path, *, crc_ok: bool = True) -> None:
    host_data = b"host"
    stream_data = b"flag{ads}"
    stream_crc = zlib.crc32(stream_data) & 0xFFFFFFFF
    if not crc_ok:
        stream_crc ^= 1
    service_name = b"STM"
    service_body = b"".join(
        (
            _vint(0x0004),
            _vint(len(stream_data)),
            _vint(0),
            stream_crc.to_bytes(4, "little"),
            _vint(0),
            _vint(0),
            _vint(len(service_name)),
            service_name,
        )
    )
    archive = b"".join(
        (
            RAR5_SIGNATURE,
            _block(1, 0, _vint(0)),
            _block(2, 0, _file_body("docs/readme.txt", host_data), data=host_data),
            _block(
                3,
                0x0020,
                service_body,
                extra=_extra(0x07, b":secret"),
                data=stream_data,
            ),
            _block(5, 0, _vint(0)),
        )
    )
    path.write_bytes(archive)


def _rar4_block(header_type: int, flags: int, body: bytes = b"", data: bytes = b"") -> bytes:
    actual_flags = flags | (RAR4_LONG_BLOCK if data else 0)
    header_size = 7 + len(body)
    header_without_crc = (
        bytes([header_type])
        + actual_flags.to_bytes(2, "little")
        + header_size.to_bytes(2, "little")
        + body
    )
    crc = zlib.crc32(header_without_crc) & 0xFFFF
    return crc.to_bytes(2, "little") + header_without_crc + data


def _rar4_file_body(name: str, data: bytes, *, sub_data: bytes = b"") -> bytes:
    name_bytes = name.encode("latin-1")
    return b"".join(
        (
            len(data).to_bytes(4, "little"),
            len(data).to_bytes(4, "little"),
            b"\x02",
            (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "little"),
            (0).to_bytes(4, "little"),
            b"\x1d",
            b"\x30",
            len(name_bytes).to_bytes(2, "little"),
            (0x20).to_bytes(4, "little"),
            name_bytes,
            sub_data,
        )
    )


def _sample_rar4(path: Path, *, crc_ok: bool = True) -> None:
    host_data = b"host"
    stream_data = b"flag{rar4_ads}"
    if not crc_ok:
        stream_data = b"flag{rar4_bad}"
    service_body = _rar4_file_body(
        "STM",
        stream_data,
        sub_data=":Zone.Identifier".encode("utf-16le"),
    )
    archive = b"".join(
        (
            RAR4_SIGNATURE,
            _rar4_block(RAR4_HEAD_MAIN, 0, b"\x00" * 6),
            _rar4_block(RAR4_HEAD_FILE, 0, _rar4_file_body("docs/readme.txt", host_data), host_data),
            _rar4_block(RAR4_HEAD_SERVICE, RAR4_LHD_SOLID, service_body, stream_data),
            _rar4_block(RAR4_HEAD_ENDARC, 0),
        )
    )
    if not crc_ok:
        # Corrupt stream bytes after header construction while keeping the
        # original header CRC32 value, mirroring a broken ADS payload.
        archive = archive.replace(b"flag{rar4_bad}", b"flag{rar4_ads}", 1)
    path.write_bytes(archive)


def test_list_rar5_ntfs_stream(tmp_path: Path) -> None:
    rar_path = tmp_path / "ads.rar"
    _sample_rar(rar_path)

    result = list_rar_ntfs_streams(rar_path)

    assert result.streams_count == 1
    stream = result.streams[0]
    assert stream["host_path"] == "docs/readme.txt"
    assert stream["stream_name"] == ":secret"
    assert stream["stream_path"] == "docs/readme.txt:secret"
    assert stream["crc_ok"] is True


def test_list_rar4_ntfs_stream(tmp_path: Path) -> None:
    rar_path = tmp_path / "ads4.rar"
    _sample_rar4(rar_path)

    result = list_rar_ntfs_streams(rar_path)

    assert result.format == "rar4"
    assert result.streams_count == 1
    stream = result.streams[0]
    assert stream["host_path"] == "docs/readme.txt"
    assert stream["service_name"] == "STM"
    assert stream["stream_name"] == ":Zone.Identifier"
    assert stream["stream_path"] == "docs/readme.txt:Zone.Identifier"
    assert stream["crc_ok"] is True


def test_extract_rar5_ntfs_stream(tmp_path: Path) -> None:
    rar_path = tmp_path / "ads.rar"
    out_dir = tmp_path / "out"
    _sample_rar(rar_path)

    result = extract_rar_ntfs_streams(rar_path, out_dir)

    payload = out_dir / "docs" / "readme.txt.streams" / "secret"
    manifest = out_dir / "ads_manifest.json"
    assert payload.read_bytes() == b"flag{ads}"
    assert manifest.exists()
    assert result.written_bytes == len(b"flag{ads}")
    assert result.streams[0]["output_path"] == str(payload)


def test_extract_rar4_ntfs_stream(tmp_path: Path) -> None:
    rar_path = tmp_path / "ads4.rar"
    out_dir = tmp_path / "out"
    _sample_rar4(rar_path)

    result = extract_rar_ntfs_streams(rar_path, out_dir)

    payload = out_dir / "docs" / "readme.txt.streams" / "Zone.Identifier"
    manifest = out_dir / "ads_manifest.json"
    assert payload.read_bytes() == b"flag{rar4_ads}"
    assert manifest.exists()
    assert result.format == "rar4"
    assert result.written_bytes == len(b"flag{rar4_ads}")
    assert result.streams[0]["output_path"] == str(payload)


def test_extract_respects_include_filter(tmp_path: Path) -> None:
    rar_path = tmp_path / "ads.rar"
    out_dir = tmp_path / "out"
    _sample_rar(rar_path)

    result = extract_rar_ntfs_streams(rar_path, out_dir, include="missing")

    assert result.streams_count == 0
    assert json.loads((out_dir / "ads_manifest.json").read_text()) == []


def test_extract_crc_mismatch_reports_status(tmp_path: Path) -> None:
    rar_path = tmp_path / "ads.rar"
    out_dir = tmp_path / "out"
    _sample_rar(rar_path, crc_ok=False)

    result = extract_rar_ntfs_streams(rar_path, out_dir)

    assert result.streams[0]["status"] == "crc_mismatch"
    assert not (out_dir / "docs" / "readme.txt.streams" / "secret").exists()


def test_extract_rar4_crc_mismatch_reports_status(tmp_path: Path) -> None:
    rar_path = tmp_path / "ads4.rar"
    out_dir = tmp_path / "out"
    _sample_rar4(rar_path, crc_ok=False)

    result = extract_rar_ntfs_streams(rar_path, out_dir)

    assert result.format == "rar4"
    assert result.streams[0]["status"] == "crc_mismatch"
    assert not (out_dir / "docs" / "readme.txt.streams" / "Zone.Identifier").exists()


def test_cli_ntfs_stream_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    rar_path = tmp_path / "ads.rar"
    out_dir = tmp_path / "out"
    _sample_rar(rar_path)

    assert main(["zip", "ntfs-stream", "list", str(rar_path), "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["streams"][0]["stream_name"] == ":secret"

    assert main(["zip", "ads", "extract", str(rar_path), "-o", str(out_dir), "--json"]) == 0
    extracted = json.loads(capsys.readouterr().out)
    assert extracted["streams_count"] == 1
    assert (out_dir / "docs" / "readme.txt.streams" / "secret").read_bytes() == b"flag{ads}"
