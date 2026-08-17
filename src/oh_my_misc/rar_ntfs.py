from __future__ import annotations

import fnmatch
import json
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"

LONG_BLOCK = 0x8000

HEAD3_MAIN = 0x73
HEAD3_FILE = 0x74
HEAD3_SERVICE = 0x7A
HEAD3_ENDARC = 0x7B

LHD_SPLIT_BEFORE = 0x0001
LHD_SPLIT_AFTER = 0x0002
LHD_PASSWORD = 0x0004
LHD_SOLID = 0x0010
LHD_LARGE = 0x0100
LHD_SALT = 0x0400

SIZEOF_FILEHEAD3 = 32
SIZE_SALT30 = 8

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
class _Rar4Block:
    header_type: int
    flags: int
    header_offset: int
    data_offset: int
    data_size: int
    header_size: int
    crc_ok: bool
    header_data: bytes
    data: bytes


@dataclass(frozen=True)
class _RarNtfsService:
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
    services, warnings, archive_format = _read_rar_ntfs_streams(
        input_path, verify_crc=verify_crc
    )
    entries = [_service_to_entry(input_path, service) for service in services]
    entries = [entry for entry in entries if _matches_stream(entry, include, glob)]
    return RarNtfsResult(
        operation="zip.ntfs-stream.list",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        format=archive_format,
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
    services, warnings, archive_format = _read_rar_ntfs_streams(
        input_path, verify_crc=verify_crc
    )
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
            error = "native extractor writes stored RAR stream data; compressed data is listed only"
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
        format=archive_format,
        backend="native",
        streams_count=len(entries),
        count=len(entries),
        written_bytes=written_bytes,
        streams=[asdict(entry) for entry in entries],
        manifest_path=manifest_path,
        warnings=warnings,
    )


def _read_rar_ntfs_streams(
    input_path: Path, *, verify_crc: bool
) -> tuple[list[_RarNtfsService], list[str], str]:
    _check_file(input_path, "RAR 文件")
    data = input_path.read_bytes()
    signature5 = data.find(RAR5_SIGNATURE)
    signature4 = data.find(RAR4_SIGNATURE)
    if signature5 >= 0 and (signature4 < 0 or signature5 <= signature4):
        services, warnings = _read_rar5_ntfs_streams_from_data(data, signature5, verify_crc)
        return services, warnings, "rar5"
    if signature4 >= 0:
        services, warnings = _read_rar4_ntfs_streams_from_data(data, signature4, verify_crc)
        return services, warnings, "rar4"
    raise ValueError(f"不是 RAR4/RAR5 文件：{input_path}")


def _read_rar5_ntfs_streams(
    input_path: Path, *, verify_crc: bool
) -> tuple[list[_RarNtfsService], list[str]]:
    _check_file(input_path, "RAR 文件")
    data = input_path.read_bytes()
    signature_offset = data.find(RAR5_SIGNATURE)
    if signature_offset < 0:
        raise ValueError(f"不是 RAR5 文件：{input_path}")
    return _read_rar5_ntfs_streams_from_data(data, signature_offset, verify_crc)


def _read_rar5_ntfs_streams_from_data(
    data: bytes, signature_offset: int, verify_crc: bool
) -> tuple[list[_RarNtfsService], list[str]]:
    offset = signature_offset + len(RAR5_SIGNATURE)
    prev_file = ""
    services: list[_RarNtfsService] = []
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
                        _RarNtfsService(
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


def _read_rar4_ntfs_streams_from_data(
    data: bytes, signature_offset: int, verify_crc: bool
) -> tuple[list[_RarNtfsService], list[str]]:
    offset = signature_offset + len(RAR4_SIGNATURE)
    prev_file = ""
    services: list[_RarNtfsService] = []
    warnings: list[str] = []
    while offset < len(data):
        block = _read_rar4_block(data, offset)
        if block is None:
            break
        if not block.crc_ok:
            warnings.append(f"header_crc_mismatch@0x{offset:x}")
        if block.header_type in {HEAD3_FILE, HEAD3_SERVICE}:
            parsed = _parse_rar4_file_or_service_header(block)
            if block.header_type == HEAD3_FILE:
                prev_file = parsed["name"]
            elif parsed["name"] == SERVICE_STREAM:
                stream_name = _decode_rar4_stream_name(parsed["sub_data"])
                if stream_name:
                    services.append(
                        _RarNtfsService(
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
                            split_before=parsed["split_before"],
                            split_after=parsed["split_after"],
                            crc_ok=_crc_ok(
                                block.data, parsed["data_crc32"], parsed["method"], verify_crc
                            ),
                            header_crc_ok=block.crc_ok,
                        )
                    )
        if block.header_type == HEAD3_ENDARC:
            break
        offset = block.data_offset + block.data_size
    return services, warnings


def _read_rar4_block(data: bytes, offset: int) -> _Rar4Block | None:
    if offset + 7 > len(data):
        return None
    header_offset = offset
    expected_crc = int.from_bytes(data[offset : offset + 2], "little")
    header_type = data[offset + 2]
    flags = int.from_bytes(data[offset + 3 : offset + 5], "little")
    header_size = int.from_bytes(data[offset + 5 : offset + 7], "little")
    if header_size < 7:
        raise ValueError(f"RAR4 header 长度无效：0x{header_offset:x}")
    header_end = offset + header_size
    if header_end > len(data):
        raise ValueError(f"RAR4 header 越界：0x{header_offset:x}")
    header_data = data[offset:header_end]
    crc_ok = (zlib.crc32(header_data[2:]) & 0xFFFF) == expected_crc
    data_size = 0
    if flags & LONG_BLOCK:
        if offset + 11 > header_end:
            raise ValueError(f"RAR4 long block 截断：0x{header_offset:x}")
        data_size = int.from_bytes(data[offset + 7 : offset + 11], "little")
    data_offset = header_end
    data_end = data_offset + data_size
    if data_end > len(data):
        raise ValueError(f"RAR4 data 越界：0x{header_offset:x}")
    return _Rar4Block(
        header_type=header_type,
        flags=flags,
        header_offset=header_offset,
        data_offset=data_offset,
        data_size=data_size,
        header_size=header_size,
        crc_ok=crc_ok,
        header_data=header_data,
        data=data[data_offset:data_end],
    )


def _parse_rar4_file_or_service_header(block: _Rar4Block) -> dict[str, Any]:
    header = block.header_data
    if len(header) < SIZEOF_FILEHEAD3:
        raise ValueError(f"RAR4 file/service header 截断：0x{block.header_offset:x}")
    low_pack_size = int.from_bytes(header[7:11], "little")
    low_unpacked_size = int.from_bytes(header[11:15], "little")
    host_os = header[15]
    data_crc32 = int.from_bytes(header[16:20], "little")
    compression_version = header[24]
    method_raw = header[25]
    method = max(0, method_raw - 0x30)
    name_size = int.from_bytes(header[26:28], "little")
    name_start = SIZEOF_FILEHEAD3
    high_pack_size = 0
    high_unpacked_size = 0
    if block.flags & LHD_LARGE:
        if len(header) < SIZEOF_FILEHEAD3 + 8:
            raise ValueError(f"RAR4 large file header 截断：0x{block.header_offset:x}")
        high_pack_size = int.from_bytes(header[name_start : name_start + 4], "little")
        high_unpacked_size = int.from_bytes(header[name_start + 4 : name_start + 8], "little")
        name_start += 8
    name_end = name_start + name_size
    if name_end > len(header):
        raise ValueError(f"RAR4 file/service name 截断：0x{block.header_offset:x}")
    name_bytes = header[name_start:name_end]
    salt_size = SIZE_SALT30 if block.flags & LHD_SALT else 0
    sub_data_end = len(header) - salt_size
    if sub_data_end < name_end:
        raise ValueError(f"RAR4 service extra 字段截断：0x{block.header_offset:x}")
    sub_data = header[name_end:sub_data_end]
    packed_size = (high_pack_size << 32) | low_pack_size
    unpacked_size = (high_unpacked_size << 32) | low_unpacked_size
    if packed_size and packed_size != block.data_size:
        packed_size = block.data_size
    return {
        "packed_size": packed_size,
        "unpacked_size": unpacked_size,
        "data_crc32": data_crc32,
        "compression_version": compression_version,
        "method": method,
        "host_os": host_os,
        "name": _decode_rar4_name(name_bytes, service=block.header_type == HEAD3_SERVICE),
        "sub_data": sub_data,
        "encrypted": bool(block.flags & LHD_PASSWORD),
        "split_before": bool(block.flags & LHD_SPLIT_BEFORE),
        "split_after": bool(block.flags & LHD_SPLIT_AFTER),
    }


def _decode_rar4_name(data: bytes, *, service: bool) -> str:
    if service:
        return data.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _decode_rar4_stream_name(data: bytes) -> str:
    if len(data) >= 2:
        try:
            text = data.decode("utf-16le", errors="strict")
            return text.split("\x00", 1)[0]
        except UnicodeDecodeError:
            pass
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


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


def _service_to_entry(input_path: Path, service: _RarNtfsService) -> RarNtfsStreamEntry:
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
