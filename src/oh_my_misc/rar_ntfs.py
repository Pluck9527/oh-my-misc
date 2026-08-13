from __future__ import annotations

import fnmatch
import json
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"

HFL_EXTRA = 0x0001
HFL_DATA = 0x0002
HFL_SPLIT_BEFORE = 0x0008
HFL_SPLIT_AFTER = 0x0010
HFL_CHILD = 0x0020

HEAD_MAIN = 1
HEAD_FILE = 2
HEAD_SERVICE = 3
HEAD_CRYPT = 4
HEAD_END = 5

FHFL_DIRECTORY = 0x0001
FHFL_UTIME = 0x0002
FHFL_CRC32 = 0x0004
FHFL_UNPUNKNOWN = 0x0008

FHEXTRA_ENCRYPTION = 0x01
FHEXTRA_SUBDATA = 0x07

SERVICE_STREAM = "STM"


@dataclass(frozen=True)
class RarNtfsStreamEntry:
    archive_path: str
    host_path: str
    stream_name: str
    stream_path: str
    service_name: str
    packed_size: int
    unpacked_size: int
    method: int
    compression_version: int
    host_os: int
    data_crc32: str
    header_offset: int
    data_offset: int
    encrypted: bool = False
    split_before: bool = False
    split_after: bool = False
    crc_ok: bool | None = None
    output_path: str = ""
    written_bytes: int = 0
    status: str = "listed"
    error: str = ""


@dataclass(frozen=True)
class RarNtfsResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    format: str
    backend: str
    streams_count: int
    count: int
    written_bytes: int
    streams: list[dict[str, Any]]
    manifest_path: str = ""
    warnings: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _Rar5Block:
    header_type: int
    flags: int
    header_offset: int
    data_offset: int
    data_size: int
    crc_ok: bool
    header_data: bytes
    data: bytes


@dataclass(frozen=True)
class _Rar5Service:
    host_path: str
    service_name: str
    stream_name: str
    packed_size: int
    unpacked_size: int
    method: int
    compression_version: int
    host_os: int
    data_crc32: int | None
    header_offset: int
    data_offset: int
    data: bytes
    encrypted: bool
    split_before: bool
    split_after: bool
    crc_ok: bool | None
    header_crc_ok: bool


def list_rar_ntfs_streams(
    input_path: Path,
    *,
    include: str = "",
    glob: str = "",
    verify_crc: bool = True,
) -> RarNtfsResult:
    services, warnings = _read_rar5_ntfs_streams(input_path, verify_crc=verify_crc)
    entries = [_service_to_entry(input_path, service) for service in services]
    entries = [entry for entry in entries if _matches_stream(entry, include, glob)]
    return RarNtfsResult(
        operation="zip.ntfs-stream.list",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        format="rar5",
        backend="native",
        streams_count=len(entries),
        count=len(entries),
        written_bytes=0,
        streams=[asdict(entry) for entry in entries],
        warnings=warnings,
    )


def extract_rar_ntfs_streams(
    input_path: Path,
    output_dir: Path,
    *,
    include: str = "",
    glob: str = "",
    overwrite: bool = False,
    manifest: bool = True,
    verify_crc: bool = True,
) -> RarNtfsResult:
    services, warnings = _read_rar5_ntfs_streams(input_path, verify_crc=verify_crc)
    output_dir.mkdir(parents=True, exist_ok=True)
    entries: list[RarNtfsStreamEntry] = []
    output_paths: list[str] = []
    written_bytes = 0
    for service in services:
        entry = _service_to_entry(input_path, service)
        if not _matches_stream(entry, include, glob):
            continue
        status = "extracted"
        error = ""
        target = _stream_output_path(output_dir, service.host_path, service.stream_name)
        data_to_write = b""
        if service.encrypted:
            status = "encrypted"
            error = "service data is encrypted"
        elif service.split_before or service.split_after:
            status = "split"
            error = "split service data is not supported by native extractor"
        elif service.method != 0:
            status = f"unsupported_method_{service.method}"
            error = (
                "native extractor writes stored RAR5 stream data; compressed data is listed only"
            )
        elif verify_crc and service.crc_ok is False:
            status = "crc_mismatch"
            error = "service data CRC32 mismatch"
        else:
            data_to_write = service.data[: service.unpacked_size]
            if target.exists() and not overwrite:
                status = "exists"
                error = "output exists; use --overwrite to replace"
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data_to_write)
                output_paths.append(str(target))
                written_bytes += len(data_to_write)
        entries.append(
            RarNtfsStreamEntry(
                archive_path=str(input_path),
                host_path=service.host_path,
                stream_name=service.stream_name,
                stream_path=f"{service.host_path}{service.stream_name}",
                service_name=service.service_name,
                packed_size=service.packed_size,
                unpacked_size=service.unpacked_size,
                method=service.method,
                compression_version=service.compression_version,
                host_os=service.host_os,
                data_crc32=_format_crc(service.data_crc32),
                header_offset=service.header_offset,
                data_offset=service.data_offset,
                encrypted=service.encrypted,
                split_before=service.split_before,
                split_after=service.split_after,
                crc_ok=service.crc_ok,
                output_path=str(target) if status == "extracted" else "",
                written_bytes=len(data_to_write) if status == "extracted" else 0,
                status=status,
                error=error,
            )
        )
    manifest_path = ""
    if manifest:
        manifest_file = output_dir / "ads_manifest.json"
        manifest_file.write_text(
            json.dumps(
                [asdict(entry) for entry in entries], ensure_ascii=False, indent=2, sort_keys=True
            ),
            encoding="utf-8",
        )
        manifest_path = str(manifest_file)
        output_paths.append(manifest_path)
    return RarNtfsResult(
        operation="zip.ntfs-stream.extract",
        input_path=str(input_path),
        output_path=str(output_dir),
        output_paths=output_paths,
        format="rar5",
        backend="native",
        streams_count=len(entries),
        count=len(entries),
        written_bytes=written_bytes,
        streams=[asdict(entry) for entry in entries],
        manifest_path=manifest_path,
        warnings=warnings,
    )


def _read_rar5_ntfs_streams(
    input_path: Path, *, verify_crc: bool
) -> tuple[list[_Rar5Service], list[str]]:
    _check_file(input_path, "RAR 文件")
    data = input_path.read_bytes()
    signature_offset = data.find(RAR5_SIGNATURE)
    if signature_offset < 0:
        if data.find(RAR4_SIGNATURE) >= 0:
            raise ValueError(
                "检测到 RAR4；native NTFS stream 当前解析 RAR5，可先用新版 WinRAR/7z 转存为 RAR5"
            )
        raise ValueError(f"不是 RAR5 文件：{input_path}")
    offset = signature_offset + len(RAR5_SIGNATURE)
    prev_file = ""
    services: list[_Rar5Service] = []
    warnings: list[str] = []
    encrypted_headers = False
    while offset < len(data):
        block = _read_rar5_block(data, offset)
        if block is None:
            break
        if not block.crc_ok:
            warnings.append(f"header_crc_mismatch@0x{offset:x}")
        reader = _VintReader(block.header_data)
        header_type = reader.read_vint()
        header_flags = reader.read_vint()
        extra_size = reader.read_vint() if header_flags & HFL_EXTRA else 0
        _data_size = reader.read_vint() if header_flags & HFL_DATA else 0
        if header_type == HEAD_CRYPT:
            encrypted_headers = True
            warnings.append("archive_has_encryption_header")
        if encrypted_headers and header_type != HEAD_CRYPT:
            warnings.append("stopped_at_encrypted_header_area")
            break
        if header_type in {HEAD_FILE, HEAD_SERVICE}:
            parsed = _parse_file_or_service_header(reader, extra_size)
            if header_type == HEAD_FILE:
                prev_file = parsed["name"]
            elif parsed["name"] == SERVICE_STREAM:
                stream_name = parsed["service_data"].decode("utf-8", errors="replace")
                if stream_name:
                    services.append(
                        _Rar5Service(
                            host_path=prev_file,
                            service_name=parsed["name"],
                            stream_name=stream_name,
                            packed_size=block.data_size,
                            unpacked_size=parsed["unpacked_size"],
                            method=parsed["method"],
                            compression_version=parsed["compression_version"],
                            host_os=parsed["host_os"],
                            data_crc32=parsed["data_crc32"],
                            header_offset=block.header_offset,
                            data_offset=block.data_offset,
                            data=block.data,
                            encrypted=parsed["encrypted"],
                            split_before=bool(block.flags & HFL_SPLIT_BEFORE),
                            split_after=bool(block.flags & HFL_SPLIT_AFTER),
                            crc_ok=_crc_ok(
                                block.data, parsed["data_crc32"], parsed["method"], verify_crc
                            ),
                            header_crc_ok=block.crc_ok,
                        )
                    )
        if header_type == HEAD_END:
            break
        offset = block.data_offset + block.data_size
    return services, warnings


def _read_rar5_block(data: bytes, offset: int) -> _Rar5Block | None:
    if offset + 4 >= len(data):
        return None
    header_offset = offset
    expected_crc = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4
    header_size, after_size = _read_vint_at(data, offset)
    header_start = after_size
    header_end = header_start + header_size
    if header_end > len(data):
        raise ValueError(f"RAR5 header 越界：0x{header_offset:x}")
    header_data = data[header_start:header_end]
    crc_ok = (zlib.crc32(data[offset:header_end]) & 0xFFFFFFFF) == expected_crc

    reader = _VintReader(header_data)
    header_type = reader.read_vint()
    flags = reader.read_vint()
    if flags & HFL_EXTRA:
        _ = reader.read_vint()
    data_size = reader.read_vint() if flags & HFL_DATA else 0
    data_offset = header_end
    data_end = data_offset + data_size
    if data_end > len(data):
        raise ValueError(f"RAR5 data 越界：0x{header_offset:x}")
    return _Rar5Block(
        header_type=header_type,
        flags=flags,
        header_offset=header_offset,
        data_offset=data_offset,
        data_size=data_size,
        crc_ok=crc_ok,
        header_data=header_data,
        data=data[data_offset:data_end],
    )


def _parse_file_or_service_header(reader: _VintReader, extra_size: int) -> dict[str, Any]:
    file_flags = reader.read_vint()
    unpacked_size = reader.read_vint()
    _attributes = reader.read_vint()
    if file_flags & FHFL_UTIME:
        reader.read_uint32()
    data_crc32 = reader.read_uint32() if file_flags & FHFL_CRC32 else None
    comp_info = reader.read_vint()
    compression_version = comp_info & 0x3F
    method = (comp_info >> 7) & 7
    host_os = reader.read_vint()
    name_length = reader.read_vint()
    name = reader.read_bytes(name_length).decode("utf-8", errors="replace")
    extra = reader.read_bytes(extra_size) if extra_size else b""
    extras = _parse_extra_records(extra)
    return {
        "file_flags": file_flags,
        "unpacked_size": unpacked_size,
        "data_crc32": data_crc32,
        "compression_version": compression_version,
        "method": method,
        "host_os": host_os,
        "name": name,
        "service_data": extras.get(FHEXTRA_SUBDATA, b""),
        "encrypted": FHEXTRA_ENCRYPTION in extras,
    }


def _parse_extra_records(extra: bytes) -> dict[int, bytes]:
    records: dict[int, bytes] = {}
    offset = 0
    while offset < len(extra):
        record_size, next_offset = _read_vint_at(extra, offset)
        record_end = next_offset + record_size
        if record_size <= 0 or record_end > len(extra):
            break
        record_type, data_offset = _read_vint_at(extra, next_offset)
        records[record_type] = extra[data_offset:record_end]
        offset = record_end
    return records


def _service_to_entry(input_path: Path, service: _Rar5Service) -> RarNtfsStreamEntry:
    return RarNtfsStreamEntry(
        archive_path=str(input_path),
        host_path=service.host_path,
        stream_name=service.stream_name,
        stream_path=f"{service.host_path}{service.stream_name}",
        service_name=service.service_name,
        packed_size=service.packed_size,
        unpacked_size=service.unpacked_size,
        method=service.method,
        compression_version=service.compression_version,
        host_os=service.host_os,
        data_crc32=_format_crc(service.data_crc32),
        header_offset=service.header_offset,
        data_offset=service.data_offset,
        encrypted=service.encrypted,
        split_before=service.split_before,
        split_after=service.split_after,
        crc_ok=service.crc_ok,
    )


def _crc_ok(data: bytes, expected: int | None, method: int, verify_crc: bool) -> bool | None:
    if expected is None or not verify_crc or method != 0:
        return None
    return (zlib.crc32(data) & 0xFFFFFFFF) == expected


def _matches_stream(entry: RarNtfsStreamEntry, include: str, glob_pattern: str) -> bool:
    haystack = f"{entry.host_path}{entry.stream_name}"
    if include and include not in haystack:
        return False
    return not (glob_pattern and not fnmatch.fnmatch(haystack, glob_pattern))


def _stream_output_path(output_dir: Path, host_path: str, stream_name: str) -> Path:
    host_parts = _safe_host_parts(host_path)
    host_parts[-1] = f"{host_parts[-1]}.streams"
    stream_file = _safe_stream_name(stream_name)
    return output_dir.joinpath(*host_parts, stream_file)


def _safe_host_parts(host_path: str) -> list[str]:
    normalized = host_path.replace("\\", "/")
    while normalized.startswith("/"):
        normalized = normalized[1:]
    parts: list[str] = []
    for raw_part in normalized.split("/"):
        part = raw_part.strip()
        if not part or part in {".", ".."}:
            continue
        parts.append(_safe_path_component(part))
    return parts or ["_host"]


def _safe_stream_name(stream_name: str) -> str:
    name = stream_name.lstrip(":")
    name = name.removesuffix(":$DATA")
    return _safe_path_component(name or "_unnamed")


def _safe_path_component(value: str) -> str:
    cleaned = "".join("_" if ch in '<>:"/\\|?*\x00' else ch for ch in value)
    cleaned = cleaned.rstrip(". ")
    return cleaned or "_"


def _format_crc(value: int | None) -> str:
    return "" if value is None else f"{value:08x}"


def _read_vint_at(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            raise ValueError("RAR5 vint 截断")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("RAR5 vint 过长")


class _VintReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read_vint(self) -> int:
        value, self.offset = _read_vint_at(self.data, self.offset)
        return value

    def read_uint32(self) -> int:
        data = self.read_bytes(4)
        return int.from_bytes(data, "little")

    def read_bytes(self, size: int) -> bytes:
        end = self.offset + size
        if size < 0 or end > len(self.data):
            raise ValueError("RAR5 字段截断")
        out = self.data[self.offset : end]
        self.offset = end
        return out


def _check_file(path: Path, label: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
