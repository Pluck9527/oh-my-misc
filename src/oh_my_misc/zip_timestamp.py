from __future__ import annotations

import calendar
import fnmatch
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class TimestampEntry:
    name: str
    path: str
    source: str
    modified_unix: int
    modified_iso: str
    created_unix: int | None = None
    created_iso: str = ""
    accessed_unix: int | None = None
    accessed_iso: str = ""
    decoded_value: int | None = None
    decoded_char: str = ""


@dataclass(frozen=True)
class ZipTimestampResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    source: str
    field: str
    base: int | None
    offset: int
    scale: int
    sort: str
    entries_count: int
    payload_bytes: int = 0
    decoded_hex: str = ""
    decoded_text: str = ""
    written_bytes: int = 0
    timestamp_entries: list[dict[str, object]] | None = None
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def list_archive_timestamps(
    input_path: Path,
    *,
    source: str = "auto",
    field: str = "modified",
    sort: str = "auto",
    include: str = "",
    glob: str = "",
    base: int | None = None,
    offset: int = 0,
    scale: int = 1,
    timezone: str = "local",
) -> ZipTimestampResult:
    entries = collect_timestamp_entries(
        input_path,
        source=source,
        field=field,
        sort=sort,
        include=include,
        glob=glob,
        base=base,
        offset=offset,
        scale=scale,
        timezone=timezone,
    )
    actual_source = _resolve_source(input_path, source)
    return ZipTimestampResult(
        operation="zip.timestamp.list",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        source=actual_source,
        field=field,
        base=base,
        offset=offset,
        scale=scale,
        sort=sort,
        entries_count=len(entries),
        timestamp_entries=[asdict(entry) for entry in entries],
        count=len(entries),
    )


def extract_timestamp_payload(
    input_path: Path,
    output_path: Path,
    *,
    base: int,
    offset: int = 0,
    scale: int = 1,
    source: str = "auto",
    field: str = "modified",
    sort: str = "auto",
    include: str = "",
    glob: str = "",
    timezone: str = "local",
) -> ZipTimestampResult:
    entries = collect_timestamp_entries(
        input_path,
        source=source,
        field=field,
        sort=sort,
        include=include,
        glob=glob,
        base=base,
        offset=offset,
        scale=scale,
        timezone=timezone,
    )
    values = [entry.decoded_value for entry in entries]
    if any(value is None for value in values):
        raise ValueError("时间戳解码失败")
    payload = bytes(_validate_byte(value) for value in values if value is not None)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    actual_source = _resolve_source(input_path, source)
    return ZipTimestampResult(
        operation="zip.timestamp.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        source=actual_source,
        field=field,
        base=base,
        offset=offset,
        scale=scale,
        sort=sort,
        entries_count=len(entries),
        payload_bytes=len(payload),
        decoded_hex=payload.hex(),
        decoded_text=payload.decode("utf-8", errors="replace"),
        written_bytes=output_path.stat().st_size,
        timestamp_entries=[asdict(entry) for entry in entries],
    )


def embed_zip_timestamps(
    input_zip: Path,
    output_zip: Path,
    *,
    payload_path: Path | None = None,
    text: str | None = None,
    base: int,
    offset: int = 0,
    scale: int = 2,
    sort: str = "archive",
    include: str = "",
    glob: str = "",
    timezone: str = "local",
) -> ZipTimestampResult:
    _check_file(input_zip, "ZIP 文件")
    if not zipfile.is_zipfile(input_zip):
        raise ValueError("timestamp embed 当前只支持 ZIP")
    payload = _load_payload(payload_path=payload_path, text=text)
    if scale <= 0:
        raise ValueError("scale 必须大于 0")
    with zipfile.ZipFile(input_zip) as source_zip:
        infos = source_zip.infolist()
        selected = _sort_zip_infos(
            [
                info
                for info in infos
                if not info.is_dir() and _matches(info.filename, include, glob)
            ],
            sort,
        )
        if len(selected) < len(payload):
            raise ValueError(f"可写入条目只有 {len(selected)} 个，不足以写入 {len(payload)} 字节")
        timestamp_by_name = {
            info.filename: _value_to_zip_datetime(
                byte, base=base, offset=offset, scale=scale, timezone=timezone
            )
            for info, byte in zip(selected, payload, strict=False)
        }
        output_zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_zip, "w") as out_zip:
            for info in infos:
                data = source_zip.read(info.filename) if not info.is_dir() else b""
                new_info = _copy_zipinfo(info)
                if info.filename in timestamp_by_name:
                    new_info.date_time = timestamp_by_name[info.filename]
                if info.is_dir():
                    out_zip.writestr(new_info, b"")
                else:
                    out_zip.writestr(new_info, data)
    entries = collect_timestamp_entries(
        output_zip,
        source="zip",
        field="modified",
        sort=sort,
        include=include,
        glob=glob,
        base=base,
        offset=offset,
        scale=scale,
        timezone=timezone,
    )[: len(payload)]
    return ZipTimestampResult(
        operation="zip.timestamp.embed",
        input_path=str(input_zip),
        output_path=str(output_zip),
        output_paths=[str(output_zip)],
        source="zip",
        field="modified",
        base=base,
        offset=offset,
        scale=scale,
        sort=sort,
        entries_count=len(entries),
        payload_bytes=len(payload),
        decoded_hex=payload.hex(),
        decoded_text=payload.decode("utf-8", errors="replace"),
        written_bytes=output_zip.stat().st_size,
        timestamp_entries=[asdict(entry) for entry in entries],
    )


def collect_timestamp_entries(
    input_path: Path,
    *,
    source: str = "auto",
    field: str = "modified",
    sort: str = "auto",
    include: str = "",
    glob: str = "",
    base: int | None = None,
    offset: int = 0,
    scale: int = 1,
    timezone: str = "local",
) -> list[TimestampEntry]:
    if scale <= 0:
        raise ValueError("scale 必须大于 0")
    _validate_field(field)
    actual_source = _resolve_source(input_path, source)
    if actual_source == "zip":
        entries = _zip_timestamp_entries(input_path, timezone=timezone)
    else:
        entries = _directory_timestamp_entries(input_path)
    filtered = [entry for entry in entries if _matches(entry.name, include, glob)]
    ordered = _sort_entries(filtered, sort=sort, source=actual_source)
    if base is None:
        return ordered
    return [
        _with_decoded(entry, field=field, base=base, offset=offset, scale=scale)
        for entry in ordered
    ]


def _zip_timestamp_entries(input_path: Path, *, timezone: str) -> list[TimestampEntry]:
    _check_file(input_path, "ZIP 文件")
    if not zipfile.is_zipfile(input_path):
        raise ValueError(f"不是有效 ZIP：{input_path}")
    entries: list[TimestampEntry] = []
    with zipfile.ZipFile(input_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            modified = _zip_datetime_to_unix(info.date_time, timezone=timezone)
            entries.append(
                TimestampEntry(
                    name=info.filename,
                    path=info.filename,
                    source="zip",
                    modified_unix=modified,
                    modified_iso=_format_unix(modified, timezone=timezone),
                )
            )
    return entries


def _directory_timestamp_entries(input_path: Path) -> list[TimestampEntry]:
    if not input_path.is_dir():
        raise FileNotFoundError(f"目录不存在：{input_path}")
    entries: list[TimestampEntry] = []
    for path in input_path.rglob("*"):
        if not path.is_file():
            continue
        stat = path.stat()
        created = int(getattr(stat, "st_birthtime", stat.st_ctime))
        modified = int(stat.st_mtime)
        accessed = int(stat.st_atime)
        name = str(path.relative_to(input_path))
        entries.append(
            TimestampEntry(
                name=name,
                path=str(path),
                source="dir",
                modified_unix=modified,
                modified_iso=_format_unix(modified, timezone="local"),
                created_unix=created,
                created_iso=_format_unix(created, timezone="local"),
                accessed_unix=accessed,
                accessed_iso=_format_unix(accessed, timezone="local"),
            )
        )
    return entries


def _with_decoded(
    entry: TimestampEntry, *, field: str, base: int, offset: int, scale: int
) -> TimestampEntry:
    timestamp = _entry_timestamp(entry, field)
    if timestamp is None:
        raise ValueError(f"条目缺少 {field} 时间：{entry.name}")
    raw = round((timestamp - base) / scale) + offset
    char = chr(raw) if 0 <= raw <= 0x10FFFF else ""
    return TimestampEntry(
        name=entry.name,
        path=entry.path,
        source=entry.source,
        modified_unix=entry.modified_unix,
        modified_iso=entry.modified_iso,
        created_unix=entry.created_unix,
        created_iso=entry.created_iso,
        accessed_unix=entry.accessed_unix,
        accessed_iso=entry.accessed_iso,
        decoded_value=raw,
        decoded_char=char,
    )


def _entry_timestamp(entry: TimestampEntry, field: str) -> int | None:
    if field == "modified":
        return entry.modified_unix
    if field == "created":
        return entry.created_unix
    if field == "accessed":
        return entry.accessed_unix
    raise ValueError(f"不支持的 field：{field}")


def _validate_byte(value: int | None) -> int:
    if value is None or not 0 <= value <= 255:
        raise ValueError(f"解码值不在字节范围 0..255：{value}")
    return value


def _resolve_source(input_path: Path, source: str) -> str:
    if source not in {"auto", "zip", "dir"}:
        raise ValueError("source 必须是 auto、zip 或 dir")
    if source != "auto":
        return source
    if input_path.is_dir():
        return "dir"
    return "zip"


def _validate_field(field: str) -> None:
    if field not in {"modified", "created", "accessed"}:
        raise ValueError("field 必须是 modified、created 或 accessed")


def _sort_entries(entries: list[TimestampEntry], *, sort: str, source: str) -> list[TimestampEntry]:
    actual_sort = (
        "archive" if sort == "auto" and source == "zip" else "numeric" if sort == "auto" else sort
    )
    if actual_sort == "archive":
        return entries
    if actual_sort == "name":
        return sorted(entries, key=lambda entry: entry.name)
    if actual_sort == "numeric":
        return sorted(entries, key=lambda entry: (_numeric_part(Path(entry.name).stem), entry.name))
    if actual_sort == "timestamp":
        return sorted(entries, key=lambda entry: (entry.modified_unix, entry.name))
    raise ValueError("sort 必须是 auto、archive、name、numeric 或 timestamp")


def _sort_zip_infos(infos: list[zipfile.ZipInfo], sort: str) -> list[zipfile.ZipInfo]:
    if sort in {"auto", "archive"}:
        return infos
    if sort == "name":
        return sorted(infos, key=lambda info: info.filename)
    if sort == "numeric":
        return sorted(
            infos, key=lambda info: (_numeric_part(Path(info.filename).stem), info.filename)
        )
    if sort == "timestamp":
        return sorted(infos, key=lambda info: (info.date_time, info.filename))
    raise ValueError("sort 必须是 auto、archive、name、numeric 或 timestamp")


def _numeric_part(name: str) -> tuple[int, str]:
    digits = "".join(ch for ch in name if ch.isdigit())
    return (int(digits), name) if digits else (10**18, name)


def _matches(name: str, include: str, glob_pattern: str) -> bool:
    if include and include not in name:
        return False
    return not (glob_pattern and not fnmatch.fnmatch(name, glob_pattern))


def _zip_datetime_to_unix(date_time: tuple[int, int, int, int, int, int], *, timezone: str) -> int:
    _validate_timezone(timezone)
    year, month, day, hour, minute, second = date_time
    time_tuple = (year, month, day, hour, minute, second, -1, -1, -1)
    if timezone == "utc":
        return calendar.timegm(time_tuple)
    return int(time.mktime(time_tuple))


def _value_to_zip_datetime(
    value: int, *, base: int, offset: int, scale: int, timezone: str
) -> tuple[int, int, int, int, int, int]:
    _validate_timezone(timezone)
    timestamp = base + (value - offset) * scale
    dt = _datetime_from_unix(timestamp, timezone=timezone)
    if not 1980 <= dt.year <= 2107:
        raise ValueError(f"ZIP 时间戳年份超出 1980..2107：{dt.isoformat(sep=' ')}")
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def _format_unix(timestamp: int, *, timezone: str) -> str:
    _validate_timezone(timezone)
    dt = _datetime_from_unix(timestamp, timezone=timezone)
    return dt.isoformat(sep=" ")


def _datetime_from_unix(timestamp: int, *, timezone: str) -> datetime:
    if timezone == "utc":
        return datetime.fromtimestamp(timestamp, tz=UTC).replace(tzinfo=None)
    return datetime.fromtimestamp(timestamp, tz=UTC).astimezone().replace(tzinfo=None)


def _validate_timezone(timezone: str) -> None:
    if timezone not in {"local", "utc"}:
        raise ValueError("timezone 必须是 local 或 utc")


def _copy_zipinfo(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    copied = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
    copied.comment = info.comment
    copied.extra = info.extra
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    copied.create_system = info.create_system
    copied.create_version = info.create_version
    copied.extract_version = info.extract_version
    copied.flag_bits = info.flag_bits
    copied.volume = info.volume
    copied.compress_type = info.compress_type
    copied._compresslevel = getattr(info, "_compresslevel", None)
    return copied


def _load_payload(*, payload_path: Path | None, text: str | None) -> bytes:
    if payload_path is None and text is None:
        raise ValueError("timestamp embed 需要 --payload 或 --text")
    if payload_path is not None and text is not None:
        raise ValueError("timestamp embed 只能指定 --payload 或 --text 之一")
    if payload_path is not None:
        _check_file(payload_path, "载荷文件")
        return payload_path.read_bytes()
    assert text is not None
    return text.encode("utf-8")


def _check_file(path: Path, label: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
