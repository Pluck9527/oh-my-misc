from __future__ import annotations

import gzip
import io
import json
import tarfile
import zipfile
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.zip_nested import detect_archive_type, unpack_nested_archives


def _zip_bytes(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def _tar_gz_bytes(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_unpack_nested_zip_chain(tmp_path: Path) -> None:
    outer = tmp_path / "outer.zip"
    output = tmp_path / "out"
    outer.write_bytes(_zip_bytes("inner.zip", _zip_bytes("flag.txt", b"flag{nested}")))

    result = unpack_nested_archives(outer, output)

    assert result.operation == "zip.nested.unpack"
    assert result.archives_processed == 2
    assert result.layers == 2
    assert any(Path(path).name == "flag.txt" for path in result.final_files)
    assert any(Path(path).read_bytes() == b"flag{nested}" for path in map(Path, result.final_files))


def test_unpack_mixed_tar_gz_and_gzip(tmp_path: Path) -> None:
    outer = tmp_path / "outer.zip"
    output = tmp_path / "out"
    gz_payload = gzip.compress(b"flag{gzip}")
    outer.write_bytes(_zip_bytes("layer.tar.gz", _tar_gz_bytes("payload.gz", gz_payload)))

    result = unpack_nested_archives(outer, output)

    assert result.archives_processed == 3
    assert any(Path(path).name == "payload" for path in result.final_files)
    assert any(Path(path).read_bytes() == b"flag{gzip}" for path in map(Path, result.final_files))


def test_detect_archive_type_by_magic_without_extension(tmp_path: Path) -> None:
    sample = tmp_path / "blob"
    sample.write_bytes(_zip_bytes("a.txt", b"a"))

    assert detect_archive_type(sample) == "zip"


def test_unpack_rejects_zip_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    output = tmp_path / "out"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../evil.txt", b"oops")

    result = unpack_nested_archives(archive, output)

    assert result.archives_processed == 0
    assert result.skipped_archives == [str(archive.resolve())]
    assert result.steps[0]["status"] == "failed"
    assert "路径越界" in result.steps[0]["message"]


def test_unpack_max_depth_skips_next_archive(tmp_path: Path) -> None:
    outer = tmp_path / "outer.zip"
    output = tmp_path / "out"
    outer.write_bytes(_zip_bytes("inner.zip", _zip_bytes("flag.txt", b"flag")))

    result = unpack_nested_archives(outer, output, max_depth=1)

    assert result.archives_processed == 1
    assert result.skipped_archives
    assert result.steps[-1]["status"] == "skipped"


def test_zip_nested_cli_json(tmp_path: Path, capsys) -> None:
    outer = tmp_path / "outer.zip"
    output = tmp_path / "out"
    outer.write_bytes(_zip_bytes("inner.zip", _zip_bytes("flag.txt", b"flag{cli}")))

    assert main(["zip", "nested", str(outer), "-o", str(output), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)

    assert data["operation"] == "zip.nested.unpack"
    assert data["archives_processed"] == 2
    assert any(Path(path).name == "flag.txt" for path in data["final_files"])
