from __future__ import annotations

import hashlib
import re
import wave
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

DeepSoundQuality = Literal["low", "normal", "high", "auto"]

_MAGIC = b"DSCF"
_MODE_TO_FACTOR: dict[str, int] = {"low": 2, "normal": 4, "high": 8}
_FACTOR_TO_MODE: dict[int, str] = {2: "low", 4: "normal", 8: "high"}
_HEADER_DECODED_SIZE = 26
_HEADER_ENCODED_SIZE = _HEADER_DECODED_SIZE * 4
_SECRET_HEADER_SIZE = 32
_FILENAME_BYTES = 20
_COMMON_SCAN_LIMIT = 882_000
_FLAG_RE = re.compile(rb"flag\{[^\r\n\x00}]{0,200}\}", re.IGNORECASE)
_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("zip", b"PK\x03\x04"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("pdf", b"%PDF-"),
    ("gif", b"GIF"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
)


@dataclass(frozen=True)
class DeepSoundResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    carrier_format: str
    found: bool
    quality: str | None
    mode: int | None
    encrypted: bool
    password_hash: str | None
    password_verified: bool | None
    data_offset: int | None
    header_offset: int | None
    sample_rate: int | None
    channels: int | None
    sample_width: int | None
    frames: int | None
    capacity_bytes: int
    embedded_bytes: int
    payload_bytes: int
    written_bytes: int
    files: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _WavData:
    blob: bytes
    data_offset: int
    data_size: int
    sample_rate: int | None
    channels: int | None
    sample_width: int | None
    frames: int | None


@dataclass(frozen=True)
class _Header:
    data_offset: int
    header_offset: int
    quality: str
    mode: int
    encrypted: bool
    password_hash: bytes | None
    decoded: bytes


@dataclass(frozen=True)
class _SecretFile:
    name: str
    size: int
    header_offset: int
    data_offset: int
    data: bytes


def analyze_deepsound(input_path: Path, *, password: str | None = None) -> DeepSoundResult:
    wav = _read_wav(input_path)
    header = _locate_header(wav)
    if header is None:
        return DeepSoundResult(
            operation="stego.deepsound.analyze",
            input_path=str(input_path),
            output_path="",
            output_paths=[],
            carrier_format="wav",
            found=False,
            quality=None,
            mode=None,
            encrypted=False,
            password_hash=None,
            password_verified=None,
            data_offset=wav.data_offset,
            header_offset=None,
            sample_rate=wav.sample_rate,
            channels=wav.channels,
            sample_width=wav.sample_width,
            frames=wav.frames,
            capacity_bytes=0,
            embedded_bytes=0,
            payload_bytes=0,
            written_bytes=0,
            files=[],
            findings=[],
        )
    decoded = _decode_payload_tail(wav, header)
    files = _parse_secret_files(decoded, encrypted=header.encrypted)
    capacity = max(0, (wav.data_size - header.header_offset - 24) // header.mode)
    payload_bytes = sum(item.size for item in files)
    return DeepSoundResult(
        operation="stego.deepsound.analyze",
        input_path=str(input_path),
        output_path="",
        output_paths=[],
        carrier_format="wav",
        found=True,
        quality=header.quality,
        mode=header.mode,
        encrypted=header.encrypted,
        password_hash=header.password_hash.hex() if header.password_hash else None,
        password_verified=_verify_password_hash(password, header.password_hash),
        data_offset=wav.data_offset,
        header_offset=header.header_offset,
        sample_rate=wav.sample_rate,
        channels=wav.channels,
        sample_width=wav.sample_width,
        frames=wav.frames,
        capacity_bytes=capacity,
        embedded_bytes=len(decoded),
        payload_bytes=payload_bytes,
        written_bytes=0,
        files=[_file_summary(item, None) for item in files],
        findings=_find_hints(b"".join(item.data for item in files)),
    )


def extract_deepsound(
    input_path: Path,
    output_path: Path,
    *,
    password: str | None = None,
    raw: bool = False,
    overwrite: bool = False,
) -> DeepSoundResult:
    wav = _read_wav(input_path)
    header = _locate_header(wav)
    if header is None:
        raise ValueError("未找到 DeepSound DSCF 头")
    if header.encrypted:
        ok = _verify_password_hash(password, header.password_hash)
        if password is None:
            raise ValueError(
                "检测到 DeepSound 加密头；analyze --json 可导出 password_hash 供字典校验"
            )
        if ok is False:
            raise ValueError("DeepSound 密码 SHA1 校验未通过")
        raise ValueError("当前原生路径已完成无密码 DeepSound；加密块请先用已知密码在原工具导出")
    decoded = _decode_payload_tail(wav, header)
    if raw:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists() and not overwrite:
            raise FileExistsError(f"输出已存在：{output_path}")
        output_path.write_bytes(decoded)
        files: list[_SecretFile] = []
        output_paths = [str(output_path)]
        written = len(decoded)
        payload_bytes = len(decoded)
    else:
        files = _parse_secret_files(decoded, encrypted=False)
        if not files:
            raise ValueError("DeepSound 头存在，但未解析到无密码 DSCF 文件头")
        output_paths = _write_secret_files(files, output_path, overwrite=overwrite)
        written = sum(len(item.data) for item in files)
        payload_bytes = written
    return DeepSoundResult(
        operation="stego.deepsound.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=output_paths,
        carrier_format="wav",
        found=True,
        quality=header.quality,
        mode=header.mode,
        encrypted=header.encrypted,
        password_hash=header.password_hash.hex() if header.password_hash else None,
        password_verified=_verify_password_hash(password, header.password_hash),
        data_offset=wav.data_offset,
        header_offset=header.header_offset,
        sample_rate=wav.sample_rate,
        channels=wav.channels,
        sample_width=wav.sample_width,
        frames=wav.frames,
        capacity_bytes=max(0, (wav.data_size - header.header_offset - 24) // header.mode),
        embedded_bytes=len(decoded),
        payload_bytes=payload_bytes,
        written_bytes=written,
        files=[_file_summary(item, output_paths[index] if index < len(output_paths) else None) for index, item in enumerate(files)],
        findings=_find_hints(b"".join(item.data for item in files) if files else decoded),
    )


def hide_deepsound(
    input_path: Path,
    output_path: Path,
    *,
    payload_paths: list[Path] | None = None,
    text: str | None = None,
    text_name: str = "message.txt",
    quality: DeepSoundQuality = "normal",
) -> DeepSoundResult:
    if quality == "auto":
        quality = "normal"
    if quality not in _MODE_TO_FACTOR:
        raise ValueError(f"DeepSound quality 必须是 low/normal/high：{quality}")
    if (text is None) == (not payload_paths):
        raise ValueError("--text 与 --payload 必须且只能使用一种")
    wav = _read_wav(input_path)
    mode = _MODE_TO_FACTOR[quality]
    payloads: list[tuple[str, bytes]] = []
    if text is not None:
        payloads.append((text_name, text.encode("utf-8")))
    else:
        for payload in payload_paths or []:
            if not payload.is_file():
                raise FileNotFoundError(f"载荷不存在：{payload}")
            payloads.append((payload.name, payload.read_bytes()))
    body = _build_unencrypted_body(payloads)
    decoded = _MAGIC + bytes([mode, 0]) + body
    encoded_size = 24 + len(body) * mode
    if encoded_size > wav.data_size:
        raise ValueError(
            f"DeepSound 容量不足：需要 {encoded_size} 个 WAV data 字节，当前 {wav.data_size}"
        )
    blob = bytearray(wav.blob)
    carrier = bytearray(blob[wav.data_offset : wav.data_offset + wav.data_size])
    _encode_data(carrier, _MAGIC + bytes([mode, 0]), 4)
    _encode_data(memoryview(carrier)[24:], body, mode)
    blob[wav.data_offset : wav.data_offset + wav.data_size] = carrier
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bytes(blob))
    files = _parse_secret_files(decoded, encrypted=False)
    return DeepSoundResult(
        operation="stego.deepsound.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        carrier_format="wav",
        found=True,
        quality=quality,
        mode=mode,
        encrypted=False,
        password_hash=None,
        password_verified=None,
        data_offset=wav.data_offset,
        header_offset=0,
        sample_rate=wav.sample_rate,
        channels=wav.channels,
        sample_width=wav.sample_width,
        frames=wav.frames,
        capacity_bytes=max(0, (wav.data_size - 24) // mode),
        embedded_bytes=len(decoded),
        payload_bytes=sum(len(data) for _, data in payloads),
        written_bytes=encoded_size,
        files=[_file_summary(item, None) for item in files],
        findings=_find_hints(b"".join(data for _, data in payloads)),
    )


def _read_wav(path: Path) -> _WavData:
    blob = path.read_bytes()
    if not (blob.startswith(b"RIFF") and blob[8:12] == b"WAVE"):
        raise ValueError("DeepSound 仅支持 RIFF/WAVE PCM 载体")
    data_offset = data_size = -1
    offset = 12
    while offset + 8 <= len(blob):
        chunk_id = blob[offset : offset + 4]
        chunk_size = int.from_bytes(blob[offset + 4 : offset + 8], "little")
        chunk_data = offset + 8
        if chunk_data + chunk_size > len(blob):
            raise ValueError("WAV chunk 长度越界")
        if chunk_id == b"data":
            data_offset = chunk_data
            data_size = chunk_size
            break
        offset = chunk_data + chunk_size + (chunk_size & 1)
    if data_offset < 0:
        raise ValueError("WAV 缺少 data chunk")
    sample_rate = channels = sample_width = frames = None
    try:
        with wave.open(str(path), "rb") as wav:
            sample_rate = wav.getframerate()
            channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            frames = wav.getnframes()
    except (EOFError, wave.Error):
        pass
    return _WavData(blob, data_offset, data_size, sample_rate, channels, sample_width, frames)


def _locate_header(wav: _WavData) -> _Header | None:
    data = wav.blob[wav.data_offset : wav.data_offset + wav.data_size]
    scan_stop = min(len(data) - _HEADER_ENCODED_SIZE, _COMMON_SCAN_LIMIT)
    if scan_stop < 0:
        return None
    for rel in range(scan_stop + 1):
        window = data[rel : rel + _HEADER_ENCODED_SIZE]
        if not _looks_like_normal_magic(window):
            continue
        decoded = _decode_data(window, 4)
        mode = decoded[4]
        encrypted = decoded[5]
        if decoded[:4] == _MAGIC and mode in _FACTOR_TO_MODE and encrypted in (0, 1):
            password_hash = decoded[6:26] if encrypted else None
            return _Header(
                data_offset=wav.data_offset,
                header_offset=rel,
                quality=_FACTOR_TO_MODE[mode],
                mode=mode,
                encrypted=bool(encrypted),
                password_hash=password_hash,
                decoded=decoded,
            )
    return None


def _looks_like_normal_magic(buf: bytes) -> bool:
    if len(buf) < 16:
        return False
    return (
        ((buf[0] & 0x0F) << 4 | (buf[2] & 0x0F)) == ord("D")
        and ((buf[4] & 0x0F) << 4 | (buf[6] & 0x0F)) == ord("S")
        and ((buf[8] & 0x0F) << 4 | (buf[10] & 0x0F)) == ord("C")
        and ((buf[12] & 0x0F) << 4 | (buf[14] & 0x0F)) == ord("F")
    )


def _decode_payload_tail(wav: _WavData, header: _Header) -> bytes:
    body_start = wav.data_offset + header.header_offset + 24
    stop = wav.data_offset + wav.data_size
    encoded = wav.blob[body_start : body_start + ((stop - body_start) // header.mode) * header.mode]
    return _MAGIC + bytes([header.mode, int(header.encrypted)]) + _decode_data(encoded, header.mode)


def _decode_data(buf: bytes | bytearray, factor: int) -> bytes:
    usable = len(buf) - (len(buf) % factor)
    out = bytearray(usable // factor)
    if factor == 2:
        out[:] = bytes(buf[0:usable:2])
    elif factor == 4:
        for index, pos in enumerate(range(0, usable, 4)):
            out[index] = ((buf[pos] & 0x0F) << 4) | (buf[pos + 2] & 0x0F)
    elif factor == 8:
        for index, pos in enumerate(range(0, usable, 8)):
            out[index] = (
                ((buf[pos] & 0x03) << 6)
                | ((buf[pos + 2] & 0x03) << 4)
                | ((buf[pos + 4] & 0x03) << 2)
                | (buf[pos + 6] & 0x03)
            )
    else:
        raise ValueError(f"未知 DeepSound mode：{factor}")
    return bytes(out)


def _encode_data(carrier: bytearray | memoryview, payload: bytes, factor: int) -> None:
    if len(payload) * factor > len(carrier):
        raise ValueError("载体容量不足")
    if factor == 2:
        for index, value in enumerate(payload):
            carrier[index * 2] = value
    elif factor == 4:
        for index, value in enumerate(payload):
            pos = index * 4
            carrier[pos] = (carrier[pos] & 0xF0) | ((value >> 4) & 0x0F)
            carrier[pos + 2] = (carrier[pos + 2] & 0xF0) | (value & 0x0F)
    elif factor == 8:
        for index, value in enumerate(payload):
            pos = index * 8
            carrier[pos] = (carrier[pos] & 0xFC) | ((value >> 6) & 0x03)
            carrier[pos + 2] = (carrier[pos + 2] & 0xFC) | ((value >> 4) & 0x03)
            carrier[pos + 4] = (carrier[pos + 4] & 0xFC) | ((value >> 2) & 0x03)
            carrier[pos + 6] = (carrier[pos + 6] & 0xFC) | (value & 0x03)
    else:
        raise ValueError(f"未知 DeepSound mode：{factor}")


def _build_unencrypted_body(payloads: list[tuple[str, bytes]]) -> bytes:
    body = bytearray()
    for name, data in payloads:
        body.extend(_build_file_header(name, len(data)))
        body.extend(data)
        body.extend(b"\x00" * ((16 - ((len(data) + 4) % 16)) % 16))
    return bytes(body)


def _build_file_header(name: str, size: int) -> bytes:
    stored_name = _deepsound_name(name).encode("ascii", "replace")[:_FILENAME_BYTES]
    return _MAGIC + stored_name.ljust(_FILENAME_BYTES, b"\x00") + size.to_bytes(4, "big") + b"\x00" * 4


def _deepsound_name(name: str) -> str:
    path_name = Path(name).name or "secret.bin"
    suffix = Path(path_name).suffix[:5]
    stem = Path(path_name).stem[:15]
    stored = f"{stem}{suffix}" if stem else path_name[:20]
    return stored[:20] or "secret.bin"


def _parse_secret_files(decoded: bytes, *, encrypted: bool) -> list[_SecretFile]:
    if encrypted:
        return []
    files: list[_SecretFile] = []
    pos = 6
    while pos + _SECRET_HEADER_SIZE <= len(decoded):
        if decoded[pos : pos + 4] != _MAGIC:
            next_index = decoded.find(_MAGIC, pos, min(len(decoded), pos + 32))
            if next_index < 0:
                break
            pos = next_index
        name_bytes = decoded[pos + 4 : pos + 24]
        size = int.from_bytes(decoded[pos + 24 : pos + 28], "big")
        data_start = pos + _SECRET_HEADER_SIZE
        data_end = data_start + size
        if data_end > len(decoded):
            break
        name = _clean_name(name_bytes) or f"hidden_{len(files)}.bin"
        files.append(_SecretFile(name=name, size=size, header_offset=pos, data_offset=data_start, data=decoded[data_start:data_end]))
        pos = data_end + ((16 - ((size + 4) % 16)) % 16)
    return files


def _clean_name(name_bytes: bytes) -> str:
    raw = name_bytes.split(b"\x00", 1)[0].strip()
    text = raw.decode("utf-8", "replace").strip()
    text = text.replace("/", "_").replace("\\", "_").replace(":", "_")
    return text


def _write_secret_files(files: list[_SecretFile], output_path: Path, *, overwrite: bool) -> list[str]:
    paths: list[str] = []
    if len(files) == 1 and output_path.suffix:
        targets = [output_path]
    else:
        output_path.mkdir(parents=True, exist_ok=True)
        targets = [_dedupe_path(output_path / item.name) for item in files]
    for item, target in zip(files, targets, strict=True):
        if target.exists() and not overwrite:
            raise FileExistsError(f"输出已存在：{target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(item.data)
        paths.append(str(target))
    return paths


def _dedupe_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for index in range(1, 10_000):
        candidate = path.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"无法生成唯一输出名：{path}")


def _file_summary(item: _SecretFile, output_path: str | None) -> dict[str, Any]:
    return {
        "name": item.name,
        "size": item.size,
        "header_offset": item.header_offset,
        "data_offset": item.data_offset,
        "sha256": hashlib.sha256(item.data).hexdigest(),
        "output_path": output_path,
    }


def _verify_password_hash(password: str | None, password_hash: bytes | None) -> bool | None:
    if password_hash is None:
        return None
    if password is None:
        return None
    return hashlib.sha1(password.encode("utf-8")).digest() == password_hash


def _find_hints(data: bytes) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for kind, signature in _SIGNATURES:
        offset = data.find(signature)
        if offset >= 0:
            findings.append({"kind": kind, "offset": offset})
    for match in _FLAG_RE.finditer(data):
        findings.append(
            {
                "kind": "flag",
                "offset": match.start(),
                "text": match.group(0).decode("utf-8", "replace"),
            }
        )
    return findings[:20]
