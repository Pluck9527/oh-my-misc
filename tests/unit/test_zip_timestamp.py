from __future__ import annotations

import json
import os
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.zip_timestamp import (
    embed_zip_timestamps,
    extract_timestamp_payload,
    list_archive_timestamps,
)

BASE_TS = 1_737_276_000


def _zip_with_names(path: Path, names: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            info = zipfile.ZipInfo(name, date_time=(2025, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, b"x")


def _zip_with_timestamp_payload(path: Path, values: bytes, *, offset: int = 0) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for index, value in enumerate(values, 1):
            timestamp = BASE_TS + value - offset
            dt = datetime.fromtimestamp(timestamp, tz=UTC).astimezone().replace(tzinfo=None)
            info = zipfile.ZipInfo(f"{index}.txt", date_time=dt.timetuple()[:6])
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, bytes([index]))


def test_zip_timestamp_extract_article_style_offset(tmp_path: Path) -> None:
    archive_path = tmp_path / "article.zip"
    output_path = tmp_path / "payload.bin"
    _zip_with_timestamp_payload(archive_path, b"ACE", offset=1)

    result = extract_timestamp_payload(
        archive_path,
        output_path,
        base=BASE_TS,
        offset=1,
        include=".txt",
        sort="archive",
    )

    assert output_path.read_bytes() == b"ACE"
    assert result.decoded_text == "ACE"
    assert [entry["decoded_char"] for entry in result.timestamp_entries or []] == list("ACE")


def test_directory_timestamp_extract_numeric_sort(tmp_path: Path) -> None:
    directory = tmp_path / "out"
    directory.mkdir()
    first = directory / "1.txt"
    second = directory / "2.txt"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    os.utime(second, (BASE_TS + ord("B"), BASE_TS + ord("B")))
    os.utime(first, (BASE_TS + ord("A"), BASE_TS + ord("A")))
    output_path = tmp_path / "dir_payload.bin"

    result = extract_timestamp_payload(
        directory,
        output_path,
        source="dir",
        base=BASE_TS,
        sort="numeric",
    )

    assert output_path.read_bytes() == b"AB"
    assert result.source == "dir"
    assert result.decoded_text == "AB"


def test_embed_zip_timestamp_roundtrip_scale2(tmp_path: Path) -> None:
    source_zip = tmp_path / "cover.zip"
    steg_zip = tmp_path / "time.zip"
    output_path = tmp_path / "payload.bin"
    _zip_with_names(source_zip, ["4.txt", "2.txt", "1.txt", "3.txt"])

    embed_result = embed_zip_timestamps(
        source_zip,
        steg_zip,
        text="flag",
        base=BASE_TS,
        scale=2,
        sort="numeric",
    )
    extract_result = extract_timestamp_payload(
        steg_zip,
        output_path,
        base=BASE_TS,
        scale=2,
        sort="numeric",
    )

    assert embed_result.payload_bytes == 4
    assert output_path.read_bytes() == b"flag"
    assert extract_result.decoded_text == "flag"


def test_timestamp_list_reports_decoded_chars(tmp_path: Path) -> None:
    archive_path = tmp_path / "list.zip"
    _zip_with_timestamp_payload(archive_path, b"ACE", offset=1)

    result = list_archive_timestamps(
        archive_path,
        base=BASE_TS,
        offset=1,
        include=".txt",
        sort="archive",
    )

    assert result.count == 3
    assert result.timestamp_entries is not None
    assert [entry["decoded_value"] for entry in result.timestamp_entries] == [65, 67, 69]
    assert [entry["decoded_char"] for entry in result.timestamp_entries] == list("ACE")


def test_cli_timestamp_json_roundtrip(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source_zip = tmp_path / "cover.zip"
    steg_zip = tmp_path / "time.zip"
    output_path = tmp_path / "payload.bin"
    _zip_with_names(source_zip, ["1.txt", "2.txt", "3.txt"])

    assert (
        main(
            [
                "zip",
                "timestamp",
                "embed",
                str(source_zip),
                "--text",
                "cat",
                "--base",
                str(BASE_TS),
                "--scale",
                "2",
                "--sort",
                "numeric",
                "-o",
                str(steg_zip),
                "--json",
            ]
        )
        == 0
    )
    embed_json = json.loads(capsys.readouterr().out)
    assert embed_json["operation"] == "zip.timestamp.embed"

    assert (
        main(
            [
                "zip",
                "timestamp",
                "extract",
                str(steg_zip),
                "--base",
                str(BASE_TS),
                "--scale",
                "2",
                "--sort",
                "numeric",
                "-o",
                str(output_path),
                "--json",
            ]
        )
        == 0
    )
    extract_json = json.loads(capsys.readouterr().out)
    assert extract_json["decoded_text"] == "cat"
    assert output_path.read_bytes() == b"cat"
