from __future__ import annotations

import bz2
import gzip
import lzma
import shutil
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

import py7zr
from py7zr import exceptions as py7zr_exceptions

ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tbz",
    ".tbz2",
    ".tar.bz2",
    ".txz",
    ".tar.xz",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
)


@dataclass(frozen=True)
class NestedArchiveStep:
    depth: int
    archive_path: str
    archive_type: str
    output_dir: str
    extracted_paths: list[str]
    next_archives: list[str]
    status: str
    message: str = ""


@dataclass(frozen=True)
class NestedArchiveResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    archives_processed: int
    layers: int
    final_files: list[str]
    skipped_archives: list[str]
    total_written_bytes: int
    steps: list[dict[str, object]]
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def unpack_nested_archives(
    input_path: Path,
    output_dir: Path,
    *,
    max_depth: int = 100,
    max_files: int = 5000,
    max_output_bytes: int = 1_000_000_000,
    password: str | None = None,
    sevenzip: Path | None = None,
    flatten_single: bool = False,
) -> NestedArchiveResult:
    """Recursively unpack nested archive files into layer directories."""

    _check_file(input_path, "压缩包")
    if max_depth < 1:
        raise ValueError("max_depth 必须大于等于 1")
    if max_files < 1:
        raise ValueError("max_files 必须大于等于 1")
    if max_output_bytes < 1:
        raise ValueError("max_output_bytes 必须大于等于 1")
    output_dir.mkdir(parents=True, exist_ok=True)
    queue: list[tuple[Path, int]] = [(input_path, 0)]
    processed: set[Path] = set()
    steps: list[NestedArchiveStep] = []
    skipped: list[str] = []
    layer = 0
    total_written = _directory_size(output_dir)

    while queue:
        archive, depth = queue.pop(0)
        archive = archive.resolve()
        if archive in processed:
            continue
        archive_type = detect_archive_type(archive)
        if archive_type is None:
            continue
        if depth >= max_depth:
            skipped.append(str(archive))
            steps.append(
                NestedArchiveStep(
                    depth=depth,
                    archive_path=str(archive),
                    archive_type=archive_type,
                    output_dir="-",
                    extracted_paths=[],
                    next_archives=[],
                    status="skipped",
                    message="超过 max_depth",
                )
            )
            continue
        processed.add(archive)
        destination = output_dir / f"layer_{layer:03d}_{_safe_stem(archive)}"
        layer += 1
        before = _directory_size(output_dir)
        try:
            extracted = _extract_archive(
                archive,
                destination,
                archive_type=archive_type,
                password=password,
                sevenzip=sevenzip,
            )
        except ValueError as error:
            skipped.append(str(archive))
            steps.append(
                NestedArchiveStep(
                    depth=depth,
                    archive_path=str(archive),
                    archive_type=archive_type,
                    output_dir=str(destination),
                    extracted_paths=[],
                    next_archives=[],
                    status="failed",
                    message=str(error),
                )
            )
            continue
        after = _directory_size(output_dir)
        total_written += max(0, after - before)
        extracted_files = [path for path in extracted if path.is_file()]
        if sum(1 for path in output_dir.rglob("*") if path.is_file()) > max_files:
            raise ValueError(f"解出文件数超过 --max-files {max_files}")
        if total_written > max_output_bytes:
            raise ValueError(f"解出总大小超过 --max-output-bytes {max_output_bytes}")
        next_archives = [path for path in extracted_files if detect_archive_type(path) is not None]
        if flatten_single and len(extracted_files) == 1 and next_archives:
            queue.insert(0, (next_archives[0], depth + 1))
        else:
            queue.extend((path, depth + 1) for path in next_archives)
        steps.append(
            NestedArchiveStep(
                depth=depth,
                archive_path=str(archive),
                archive_type=archive_type,
                output_dir=str(destination),
                extracted_paths=[str(path) for path in extracted_files],
                next_archives=[str(path) for path in next_archives],
                status="extracted",
            )
        )

    all_extracted_files = [path for path in output_dir.rglob("*") if path.is_file()]
    archive_outputs = {path.resolve() for step in steps for path in map(Path, step.next_archives)}
    final_files = [
        str(path) for path in all_extracted_files if path.resolve() not in archive_outputs
    ]
    return NestedArchiveResult(
        operation="zip.nested.unpack",
        input_path=str(input_path),
        output_path=str(output_dir),
        output_paths=[str(path) for path in all_extracted_files],
        archives_processed=sum(1 for step in steps if step.status == "extracted"),
        layers=layer,
        final_files=final_files,
        skipped_archives=skipped,
        total_written_bytes=sum(path.stat().st_size for path in all_extracted_files),
        steps=[asdict(step) for step in steps],
    )


def detect_archive_type(path: Path) -> str | None:
    if not path.is_file():
        return None
    with path.open("rb") as handle:
        magic = handle.read(8)
    lower_name = path.name.lower()
    if zipfile.is_zipfile(path):
        return "zip"
    try:
        if tarfile.is_tarfile(path):
            if lower_name.endswith((".tar.gz", ".tgz")):
                return "tar.gz"
            if lower_name.endswith((".tar.bz2", ".tbz", ".tbz2")):
                return "tar.bz2"
            if lower_name.endswith((".tar.xz", ".txz")):
                return "tar.xz"
            return "tar"
    except (tarfile.TarError, OSError):
        pass
    if magic.startswith(b"\x1f\x8b"):
        return "gzip"
    if magic.startswith(b"BZh"):
        return "bzip2"
    if magic.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if magic.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if magic.startswith(b"Rar!\x1a\x07"):
        return "rar"
    return None


def _extract_archive(
    archive: Path,
    destination: Path,
    *,
    archive_type: str,
    password: str | None,
    sevenzip: Path | None,
) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    if archive_type == "zip":
        return _extract_zip(archive, destination, password=password)
    if archive_type.startswith("tar"):
        return _extract_tar(archive, destination)
    if archive_type == "gzip":
        return [_extract_single_stream(archive, destination, opener=gzip.open)]
    if archive_type == "bzip2":
        return [_extract_single_stream(archive, destination, opener=bz2.open)]
    if archive_type == "xz":
        return [_extract_single_stream(archive, destination, opener=lzma.open)]
    if archive_type == "7z":
        return _extract_7z_native(archive, destination, password=password, sevenzip=sevenzip)
    if archive_type == "rar":
        raise ValueError("RAR 原生解包未实现")
    raise ValueError(f"不支持的压缩类型：{archive_type}")


def _extract_zip(archive: Path, destination: Path, *, password: str | None) -> list[Path]:
    extracted: list[Path] = []
    pwd = password.encode("utf-8") if password is not None else None
    try:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                target = _safe_join(destination, info.filename)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, pwd=pwd) as source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink)
                extracted.append(target)
    except RuntimeError as error:
        raise ValueError(f"ZIP 解压失败，可能需要密码：{error}") from error
    except zipfile.BadZipFile as error:
        raise ValueError(f"ZIP 解压失败：{error}") from error
    return extracted


def _extract_tar(archive: Path, destination: Path) -> list[Path]:
    extracted: list[Path] = []
    try:
        with tarfile.open(archive) as tf:
            for member in tf.getmembers():
                target = _safe_join(destination, member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tf.extractfile(member)
                if source is None:
                    continue
                with source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink)
                extracted.append(target)
    except tarfile.TarError as error:
        raise ValueError(f"TAR 解压失败：{error}") from error
    return extracted


def _extract_single_stream(archive: Path, destination: Path, *, opener: object) -> Path:
    output_name = _strip_compression_suffix(archive.name)
    output_path = _safe_join(destination, output_name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with opener(archive, "rb") as source, output_path.open("wb") as sink:  # type: ignore[operator]
        shutil.copyfileobj(source, sink)
    return output_path


def _extract_7z_native(
    archive: Path,
    destination: Path,
    *,
    password: str | None,
    sevenzip: Path | None,
) -> list[Path]:
    _ = sevenzip
    before = {path.resolve() for path in destination.rglob("*") if path.is_file()}
    try:
        with py7zr.SevenZipFile(archive, mode="r", password=password) as archive_file:
            for name in archive_file.getnames():
                _safe_join(destination, name.replace("\\", "/"))
            archive_file.extractall(path=destination)
    except py7zr_exceptions.PasswordRequired as error:
        raise ValueError("7z 解压失败，需要密码") from error
    except (
        py7zr_exceptions.ArchiveError,
        py7zr_exceptions.DecompressionError,
        py7zr_exceptions.UnsupportedCompressionMethodError,
        lzma.LZMAError,
        OSError,
    ) as error:
        raise ValueError(f"7z 原生解压失败：{error}") from error
    after = [path for path in destination.rglob("*") if path.is_file()]
    for path in after:
        _safe_join(destination, str(path.relative_to(destination)))
    return [path for path in after if path.resolve() not in before]


def _safe_join(root: Path, name: str) -> Path:
    target = (root / name).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"压缩包条目路径越界：{name}")
    return target


def _strip_compression_suffix(name: str) -> str:
    lower = name.lower()
    for suffix in (".gz", ".bz2", ".xz", ".zst"):
        if lower.endswith(suffix):
            return name[: -len(suffix)] or "decompressed.bin"
    return name + ".out"


def _safe_stem(path: Path) -> str:
    name = path.name
    for suffix in ARCHIVE_SUFFIXES:
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
            break
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    return cleaned[:80] or "archive"


def _directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
