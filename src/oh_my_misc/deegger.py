from __future__ import annotations

import datetime as _dt
import os
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from struct import pack, unpack_from

BREAK_STOP_TEXT = "$#&)*@&(#^*"
BREAK_START_TEXT = "&)($#^@*#^("
BREAK_START = BREAK_START_TEXT.encode("ascii") + b"\x00"
BREAK_STOP = BREAK_STOP_TEXT.encode("ascii") + b"\x00"
CAB_MULTI_EXTENSION = ".1"


@dataclass(frozen=True)
class DeEggerEntry:
    name: str
    size: int
    output_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DeEggerResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    host_bytes: int
    payload_bytes: int
    embedded_bytes: int
    written_bytes: int
    extension: str
    marker_found: bool
    start_offset: int = -1
    stop_offset: int = -1
    encrypted: bool = True
    multi_file: bool = False
    unpacked: bool = False
    entries: list[dict[str, object]] | None = None
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def hide_deegger(
    host_path: Path,
    output_path: Path,
    *,
    payload_paths: list[Path] | None = None,
    text: str | None = None,
    text_name: str = "message.txt",
) -> DeEggerResult:
    """Embed one file, multiple files, or text using DeEgger Embedder's format."""

    host = _read_file(host_path, "宿主文件")
    if find_deegger_payload(host).marker_found:
        raise ValueError("宿主已包含 DeEgger 隐藏文件，原工具会拒绝重复嵌入")
    payload, extension, entries = _build_payload(payload_paths=payload_paths, text=text, text_name=text_name)
    extension_bytes = _encode_extension(extension)
    hidden_bytes = _invert_bytes(payload)
    output = host + BREAK_START + hidden_bytes + BREAK_STOP + extension_bytes
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output)
    return DeEggerResult(
        operation="stego.deegger.hide",
        input_path=str(host_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        host_bytes=len(host),
        payload_bytes=sum(entry.size for entry in entries),
        embedded_bytes=len(payload),
        written_bytes=len(output),
        extension=extension,
        marker_found=True,
        start_offset=len(host),
        stop_offset=len(host) + len(BREAK_START) + len(hidden_bytes),
        multi_file=extension.lower() == CAB_MULTI_EXTENSION,
        entries=[entry.to_dict() for entry in entries],
        count=1,
    )


def extract_deegger(
    input_path: Path,
    output_path: Path,
    *,
    unpack: bool = False,
) -> DeEggerResult:
    """Extract a DeEgger hidden payload, optionally unpacking embedded CAB files."""

    data = _read_file(input_path, "DeEgger 载体")
    payload = find_deegger_payload(data)
    if not payload.marker_found:
        raise ValueError("未找到 DeEgger 起止标记")
    hidden = _invert_bytes(payload.hidden_bytes)
    extension = _decode_extension(payload.extension_bytes)
    output_paths: list[str] = []
    entries: list[DeEggerEntry]
    written = 0
    is_cab = extension.lower() == CAB_MULTI_EXTENSION and hidden.startswith(b"MSCF")
    if unpack or is_cab and output_path.suffix == "":
        if not is_cab:
            raise ValueError("当前载荷不是 DeEgger 多文件 CAB，不能 extract-files")
        entries = extract_cab_bytes(hidden, output_path)
        output_paths = [entry.output_path for entry in entries]
        written = sum(entry.size for entry in entries)
        operation = "stego.deegger.extract-files"
        unpacked = True
    else:
        final_output = _with_detected_extension(output_path, extension)
        final_output.parent.mkdir(parents=True, exist_ok=True)
        final_output.write_bytes(hidden)
        output_paths = [str(final_output)]
        entries = [DeEggerEntry(final_output.name, len(hidden), str(final_output))]
        written = len(hidden)
        operation = "stego.deegger.extract"
        unpacked = False
    return DeEggerResult(
        operation=operation,
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=output_paths,
        host_bytes=payload.start_offset,
        payload_bytes=len(hidden),
        embedded_bytes=len(payload.hidden_bytes),
        written_bytes=written,
        extension=extension,
        marker_found=True,
        start_offset=payload.start_offset,
        stop_offset=payload.stop_offset,
        multi_file=is_cab,
        unpacked=unpacked,
        entries=[entry.to_dict() for entry in entries],
        count=len(entries) if entries else 1,
    )


def inspect_deegger(input_path: Path) -> DeEggerResult:
    data = _read_file(input_path, "DeEgger 载体")
    payload = find_deegger_payload(data)
    if not payload.marker_found:
        return DeEggerResult(
            operation="stego.deegger.inspect",
            input_path=str(input_path),
            output_path="",
            output_paths=[],
            host_bytes=len(data),
            payload_bytes=0,
            embedded_bytes=0,
            written_bytes=0,
            extension="",
            marker_found=False,
            count=0,
        )
    hidden = _invert_bytes(payload.hidden_bytes)
    extension = _decode_extension(payload.extension_bytes)
    entries: list[dict[str, object]] = []
    multi_file = extension.lower() == CAB_MULTI_EXTENSION and hidden.startswith(b"MSCF")
    if multi_file:
        try:
            entries = [entry.to_dict() for entry in list_cab_bytes(hidden)]
        except ValueError:
            entries = []
    return DeEggerResult(
        operation="stego.deegger.inspect",
        input_path=str(input_path),
        output_path="",
        output_paths=[],
        host_bytes=payload.start_offset,
        payload_bytes=len(hidden),
        embedded_bytes=len(payload.hidden_bytes),
        written_bytes=0,
        extension=extension,
        marker_found=True,
        start_offset=payload.start_offset,
        stop_offset=payload.stop_offset,
        multi_file=multi_file,
        entries=entries,
        count=len(entries) if entries else 1,
    )


@dataclass(frozen=True)
class _PayloadSlice:
    marker_found: bool
    start_offset: int = -1
    hidden_start: int = -1
    stop_offset: int = -1
    hidden_bytes: bytes = b""
    extension_bytes: bytes = b""


def find_deegger_payload(data: bytes) -> _PayloadSlice:
    start = data.find(BREAK_START)
    if start < 0:
        return _PayloadSlice(False)
    hidden_start = start + len(BREAK_START)
    stop = data.find(BREAK_STOP, hidden_start)
    if stop < 0:
        return _PayloadSlice(False, start_offset=start, hidden_start=hidden_start)
    extension_start = stop + len(BREAK_STOP)
    return _PayloadSlice(
        True,
        start_offset=start,
        hidden_start=hidden_start,
        stop_offset=stop,
        hidden_bytes=data[hidden_start:stop],
        extension_bytes=data[extension_start:],
    )


def _build_payload(
    *,
    payload_paths: list[Path] | None,
    text: str | None,
    text_name: str,
) -> tuple[bytes, str, list[DeEggerEntry]]:
    paths = payload_paths or []
    if (text is None) == (not paths):
        raise ValueError("--text 与 --payload 必须且只能提供一种")
    if text is not None:
        data = text.encode("utf-8")
        extension = Path(text_name).suffix
        return data, extension, [DeEggerEntry(text_name, len(data))]
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"载荷不存在：{path}")
    if len(paths) == 1:
        payload = paths[0].read_bytes()
        return payload, paths[0].suffix, [DeEggerEntry(paths[0].name, len(payload))]
    entries = [DeEggerEntry(path.name, path.stat().st_size) for path in paths]
    return create_cab_bytes(paths), CAB_MULTI_EXTENSION, entries


def _read_file(path: Path, label: str) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
    return path.read_bytes()


def _invert_bytes(data: bytes) -> bytes:
    return bytes(byte ^ 0xFF for byte in data)


def _encode_extension(extension: str) -> bytes:
    raw = extension.encode("latin1", errors="replace") + b"\x00"
    return _invert_bytes(raw)


def _decode_extension(data: bytes) -> str:
    raw = _invert_bytes(data)
    chars = bytearray()
    for byte in raw:
        if byte in {0x00, 0xFF}:
            break
        chars.append(byte)
    return chars.decode("latin1", errors="replace")


def _with_detected_extension(output_path: Path, extension: str) -> Path:
    if not extension or output_path.suffix:
        return output_path
    return output_path.with_suffix(extension)


def create_cab_bytes(paths: list[Path]) -> bytes:
    """Create a simple uncompressed Cabinet compatible with DeEgger multi-hidden mode."""

    file_payloads = [(path.name, path.read_bytes(), path.stat().st_mtime) for path in paths]
    folder_data = b"".join(content for _, content, _ in file_payloads)
    chunks = [folder_data[index : index + 32768] for index in range(0, len(folder_data), 32768)]
    if not chunks:
        chunks = [b""]
    header_len = 36
    folder_len = 8
    file_offset = 0
    cffile_entries = bytearray()
    for name, content, mtime in file_payloads:
        dos_date, dos_time = _dos_datetime(mtime)
        name_bytes = _cab_safe_name(name).encode("utf-8") + b"\x00"
        cffile_entries += pack(
            "<IIHHHH",
            len(content),
            file_offset,
            0,
            dos_date,
            dos_time,
            0x20,
        )
        cffile_entries += name_bytes
        file_offset += len(content)
    coff_files = header_len + folder_len
    coff_cab_start = coff_files + len(cffile_entries)
    cfdata_entries = bytearray()
    for chunk in chunks:
        cfdata_entries += pack("<IHH", 0, len(chunk), len(chunk)) + chunk
    cb_cabinet = coff_cab_start + len(cfdata_entries)
    header = pack(
        "<4sIIIIIBBHHHHH",
        b"MSCF",
        0,
        cb_cabinet,
        0,
        coff_files,
        0,
        3,
        1,
        1,
        len(file_payloads),
        0,
        1234,
        0,
    )
    folder = pack("<IHH", coff_cab_start, len(chunks), 0)
    return header + folder + bytes(cffile_entries) + bytes(cfdata_entries)


def list_cab_bytes(data: bytes) -> list[DeEggerEntry]:
    files, _folders = _parse_cab(data, materialize=False)
    return [DeEggerEntry(name, size) for name, size, _offset, _folder in files]


def extract_cab_bytes(data: bytes, output_dir: Path) -> list[DeEggerEntry]:
    files, folders = _parse_cab(data, materialize=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    entries: list[DeEggerEntry] = []
    for name, size, offset, folder_index in files:
        safe_name = _cab_safe_name(name)
        out_path = output_dir / safe_name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        content = folders[folder_index][offset : offset + size]
        out_path.write_bytes(content)
        entries.append(DeEggerEntry(safe_name, len(content), str(out_path)))
    return entries


def _parse_cab(data: bytes, *, materialize: bool) -> tuple[list[tuple[str, int, int, int]], list[bytes]]:
    if len(data) < 36 or data[:4] != b"MSCF":
        raise ValueError("不是 Microsoft Cabinet 文件")
    (
        _signature,
        _reserved1,
        _cb_cabinet,
        _reserved2,
        coff_files,
        _reserved3,
        _version_minor,
        _version_major,
        c_folders,
        c_files,
        flags,
        _set_id,
        _i_cabinet,
    ) = unpack_from("<4sIIIIIBBHHHHH", data, 0)
    position = 36
    cb_cf_folder = 0
    cb_cf_data = 0
    if flags & 0x0004:
        cb_cf_header, cb_cf_folder, cb_cf_data = unpack_from("<HBB", data, position)
        position += 4 + cb_cf_header
    if flags & 0x0001:
        position = _skip_cabinet_string(data, _skip_cabinet_string(data, position))
    if flags & 0x0002:
        position = _skip_cabinet_string(data, _skip_cabinet_string(data, position))
    folders: list[tuple[int, int, int]] = []
    for _ in range(c_folders):
        coff_cab_start, c_cfdata, type_compress = unpack_from("<IHH", data, position)
        folders.append((coff_cab_start, c_cfdata, type_compress))
        position += 8 + cb_cf_folder
    files: list[tuple[str, int, int, int]] = []
    position = coff_files
    for _ in range(c_files):
        size, offset, folder_index, _date, _time, _attribs = unpack_from("<IIHHHH", data, position)
        position += 16
        end = data.index(b"\x00", position)
        name = data[position:end].decode("utf-8", errors="replace")
        files.append((name, size, offset, folder_index))
        position = end + 1
    if not materialize:
        return files, []
    folder_bytes = [
        _read_cab_folder(data, folder, cb_cf_data) for folder in folders
    ]
    return files, folder_bytes


def _read_cab_folder(data: bytes, folder: tuple[int, int, int], cb_cf_data: int) -> bytes:
    coff_cab_start, c_cfdata, type_compress = folder
    method = type_compress & 0x000F
    position = coff_cab_start
    output = bytearray()
    for _ in range(c_cfdata):
        _checksum, cb_data, cb_uncomp = unpack_from("<IHH", data, position)
        position += 8 + cb_cf_data
        block = data[position : position + cb_data]
        position += cb_data
        if method == 0:
            decoded = block
        elif method == 1:
            decoded = _decompress_mszip_block(block, bytes(output[-32768:]))
        else:
            raise ValueError(f"不支持的 CAB 压缩方式：{method}")
        if len(decoded) != cb_uncomp:
            raise ValueError(f"CAB 数据块长度异常：{len(decoded)} != {cb_uncomp}")
        output += decoded
    return bytes(output)


def _decompress_mszip_block(block: bytes, dictionary: bytes) -> bytes:
    if not block.startswith(b"CK"):
        raise ValueError("MSZIP 数据块缺少 CK 头")
    stream = block[2:]
    if dictionary:
        obj = zlib.decompressobj(wbits=-15, zdict=dictionary)
        return obj.decompress(stream) + obj.flush()
    return zlib.decompress(stream, -15)


def _skip_cabinet_string(data: bytes, position: int) -> int:
    return data.index(b"\x00", position) + 1


def _dos_datetime(timestamp: float) -> tuple[int, int]:
    try:
        dt = _dt.datetime.fromtimestamp(timestamp, tz=_dt.UTC)
    except (OverflowError, OSError, ValueError):
        dt = _dt.datetime(1980, 1, 1, tzinfo=_dt.UTC)
    year = min(max(dt.year, 1980), 2107)
    dos_date = ((year - 1980) << 9) | (dt.month << 5) | dt.day
    dos_time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return dos_date, dos_time


def _cab_safe_name(name: str) -> str:
    parts = [part for part in Path(name).parts if part not in {"", os.curdir, os.pardir}]
    safe = Path(*parts).as_posix() if parts else "payload.bin"
    return safe.replace("\\", "/")
