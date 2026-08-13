from __future__ import annotations

import gzip
import os
import shutil
import struct
import subprocess
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from hashlib import sha1
from pathlib import Path
from typing import Any, Literal

from Crypto.Cipher import DES3

COUNT_MAX = 3
EMBED = 1
DONT_EMBED = 0
DO_NOTHING = 2
DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024

MPEG_VERSIONS = {0: "2.5", 2: "2", 3: "1"}
BITRATES_LAYER3 = {
    3: (None, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, None),
    2: (None, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, None),
    0: (None, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, None),
}
SAMPLE_RATES = {
    3: (44100, 48000, 32000, None),
    2: (22050, 24000, 16000, None),
    0: (11025, 12000, 8000, None),
}
CHANNEL_MODES = ("stereo", "joint-stereo", "dual-channel", "mono")


@dataclass(frozen=True)
class MP3StegoFrame:
    index: int
    offset: int
    version: str
    bitrate_kbps: int
    sample_rate: int
    channels: int
    channel_mode: str
    frame_length: int
    side_info_offset: int
    side_info_bytes: int
    part2_3_lengths: list[int]
    hidden_bits: list[int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MP3StegoResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    password_used: bool
    found_password: str | None
    length_size: int
    frames: int
    candidate_bits: int
    selected_bits: int
    embedded_bytes: int
    payload_bytes: int
    raw_bytes: int
    decoded: bool
    decrypted: bool
    uncompressed: bool
    attempts: int
    executable: str
    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    written_bytes: int
    frame_entries: list[dict[str, Any]]
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _Header:
    offset: int
    version_id: int
    version: str
    bitrate_kbps: int
    sample_rate: int
    padding: int
    channels: int
    channel_mode: str
    frame_length: int
    side_info_offset: int
    side_info_bytes: int
    granules: int
    protected_by_crc: bool


@dataclass(frozen=True)
class _HiddenPacket:
    raw: bytes
    selected_bits: int
    embedded_bytes: int
    length_size: int


def inspect_mp3stego(
    input_path: Path,
    *,
    password: str = "",
    length_size: int | Literal["auto"] = 4,
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
) -> MP3StegoResult:
    frames = parse_mp3_frames(input_path)
    bits = [bit for frame in frames for bit in frame.hidden_bits]
    selected_bits = _count_selected_bits(bits, password)
    packet = _try_extract_packet(
        bits,
        password=password,
        length_size=length_size,
        max_payload_bytes=max_payload_bytes,
    )
    return MP3StegoResult(
        operation="audio.mp3stego.inspect",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        mode="inspect",
        password_used=bool(password),
        found_password=password if password else None,
        length_size=packet.length_size
        if packet is not None
        else _normalise_length_size(length_size),
        frames=len(frames),
        candidate_bits=len(bits),
        selected_bits=selected_bits,
        embedded_bytes=packet.embedded_bytes if packet is not None else 0,
        payload_bytes=0,
        raw_bytes=len(packet.raw) if packet is not None else 0,
        decoded=False,
        decrypted=False,
        uncompressed=False,
        attempts=1,
        executable="",
        command=[],
        stdout="",
        stderr="",
        returncode=0,
        written_bytes=0,
        frame_entries=[frame.to_dict() for frame in frames[:10]],
        count=len(frames),
    )


def extract_mp3stego(
    input_path: Path,
    output_path: Path,
    *,
    password: str = "",
    length_size: int | Literal["auto"] = 4,
    raw: bool = False,
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
) -> MP3StegoResult:
    frames = parse_mp3_frames(input_path)
    bits = [bit for frame in frames for bit in frame.hidden_bits]
    packet = _extract_packet(
        bits,
        password=password,
        length_size=length_size,
        max_payload_bytes=max_payload_bytes,
    )
    payload = packet.raw if raw else decode_mp3stego_payload(packet.raw, password=password)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    written_bytes = output_path.stat().st_size
    return MP3StegoResult(
        operation="audio.mp3stego.extract-raw" if raw else "audio.mp3stego.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="raw" if raw else "decode",
        password_used=bool(password),
        found_password=password if password else "",
        length_size=packet.length_size,
        frames=len(frames),
        candidate_bits=len(bits),
        selected_bits=packet.selected_bits,
        embedded_bytes=packet.embedded_bytes,
        payload_bytes=0 if raw else len(payload),
        raw_bytes=len(packet.raw),
        decoded=not raw,
        decrypted=not raw,
        uncompressed=not raw,
        attempts=1,
        executable="",
        command=[],
        stdout="",
        stderr="",
        returncode=0,
        written_bytes=written_bytes,
        frame_entries=[],
    )


def brute_mp3stego(
    input_path: Path,
    wordlist: Path,
    output_path: Path,
    *,
    length_size: int | Literal["auto"] = 4,
    include_default: bool = True,
    contains: bytes | None = None,
    prefix: bytes | None = None,
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
    encoding: str = "utf-8",
) -> MP3StegoResult:
    frames = parse_mp3_frames(input_path)
    bits = [bit for frame in frames for bit in frame.hidden_bits]
    attempts = 0
    last_packet: _HiddenPacket | None = None
    candidates = _iter_passwords(wordlist, include_default=include_default, encoding=encoding)
    for password in candidates:
        attempts += 1
        try:
            packet = _extract_packet(
                bits,
                password=password,
                length_size=length_size,
                max_payload_bytes=max_payload_bytes,
            )
            payload = decode_mp3stego_payload(packet.raw, password=password)
        except (ValueError, OSError):
            continue
        last_packet = packet
        if contains is not None and contains not in payload:
            continue
        if prefix is not None and not payload.startswith(prefix):
            continue
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        return MP3StegoResult(
            operation="audio.mp3stego.brute",
            input_path=str(input_path),
            output_path=str(output_path),
            output_paths=[str(output_path)],
            mode="brute",
            password_used=bool(password),
            found_password=password,
            length_size=packet.length_size,
            frames=len(frames),
            candidate_bits=len(bits),
            selected_bits=packet.selected_bits,
            embedded_bytes=packet.embedded_bytes,
            payload_bytes=len(payload),
            raw_bytes=len(packet.raw),
            decoded=True,
            decrypted=True,
            uncompressed=True,
            attempts=attempts,
            executable="",
            command=[],
            stdout="",
            stderr="",
            returncode=0,
            written_bytes=output_path.stat().st_size,
            frame_entries=[],
        )
    raise ValueError(
        "no MP3Stego password candidate produced a valid payload"
        + (f" after {attempts} attempts" if attempts else "")
        + (f"; last embedded size was {last_packet.embedded_bytes}" if last_packet else "")
    )


def encode_mp3stego(
    input_path: Path,
    output_path: Path,
    *,
    payload_path: Path,
    password: str = "",
    encoder: Path | None = None,
) -> MP3StegoResult:
    executable = _resolve_mp3stego_tool("encoder", encoder)
    command = [
        str(executable),
        "-E",
        str(payload_path),
        "-P",
        password,
        str(input_path),
        str(output_path),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = (
            completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        )
        raise ValueError(f"MP3Stego encoder failed: {detail}")
    output_path = Path(output_path)
    if not output_path.exists():
        raise ValueError("MP3Stego encoder finished without producing the requested MP3")
    return MP3StegoResult(
        operation="audio.mp3stego.encode-tool",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="encode-tool",
        password_used=bool(password),
        found_password=password if password else "",
        length_size=4,
        frames=0,
        candidate_bits=0,
        selected_bits=0,
        embedded_bytes=Path(payload_path).stat().st_size,
        payload_bytes=Path(payload_path).stat().st_size,
        raw_bytes=0,
        decoded=False,
        decrypted=False,
        uncompressed=False,
        attempts=1,
        executable=str(executable),
        command=command,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        written_bytes=output_path.stat().st_size,
        frame_entries=[],
    )


def parse_mp3_frames(input_path: Path) -> list[MP3StegoFrame]:
    data = Path(input_path).read_bytes()
    frames: list[MP3StegoFrame] = []
    pos = _skip_id3v2(data)
    while pos + 4 <= len(data):
        header = _parse_header(data, pos)
        if header is None:
            pos += 1
            continue
        if header.side_info_offset + header.side_info_bytes > len(data):
            pos += 1
            continue
        if header.offset + header.frame_length > len(data):
            pos += 1
            continue
        side_info = data[header.side_info_offset : header.side_info_offset + header.side_info_bytes]
        try:
            lengths = _parse_side_info_lengths(side_info, header)
        except ValueError:
            pos += 1
            continue
        bits = [value & 1 for value in lengths]
        frames.append(
            MP3StegoFrame(
                index=len(frames),
                offset=header.offset,
                version=header.version,
                bitrate_kbps=header.bitrate_kbps,
                sample_rate=header.sample_rate,
                channels=header.channels,
                channel_mode=header.channel_mode,
                frame_length=header.frame_length,
                side_info_offset=header.side_info_offset,
                side_info_bytes=header.side_info_bytes,
                part2_3_lengths=lengths,
                hidden_bits=bits,
            )
        )
        pos = header.offset + header.frame_length
    if not frames:
        raise ValueError("no MPEG Layer III frames found")
    return frames


def decode_mp3stego_payload(raw: bytes, *, password: str = "") -> bytes:
    decrypted = _decrypt_mp3stego_bytes(raw, password=password)
    try:
        return gzip.decompress(decrypted)
    except OSError as error:
        raise ValueError(f"MP3Stego gzip payload could not be decompressed: {error}") from error


def _extract_packet(
    bits: list[int],
    *,
    password: str,
    length_size: int | Literal["auto"],
    max_payload_bytes: int,
) -> _HiddenPacket:
    packet = _try_extract_packet(
        bits,
        password=password,
        length_size=length_size,
        max_payload_bytes=max_payload_bytes,
    )
    if packet is None:
        raise ValueError(
            "not enough selected MP3Stego bits to recover the embedded length and body"
        )
    return packet


def _try_extract_packet(
    bits: list[int],
    *,
    password: str,
    length_size: int | Literal["auto"],
    max_payload_bytes: int,
) -> _HiddenPacket | None:
    sizes = (4, 8) if length_size == "auto" else (_normalise_length_size(length_size),)
    errors: list[ValueError] = []
    for size in sizes:
        try:
            return _extract_packet_with_length_size(
                bits, password=password, length_size=size, max_payload_bytes=max_payload_bytes
            )
        except ValueError as error:
            errors.append(error)
    return None


def _extract_packet_with_length_size(
    bits: list[int],
    *,
    password: str,
    length_size: int,
    max_payload_bytes: int,
) -> _HiddenPacket:
    selected: list[int] = []
    prng = _MP3StegoPRNG(password)
    embedded_bytes: int | None = None
    required_bits: int | None = None
    for bit in bits:
        if prng.next() != EMBED:
            continue
        selected.append(bit)
        if embedded_bytes is None and len(selected) >= length_size * 8:
            header = _bits_to_bytes(selected[: length_size * 8])
            embedded_bytes = int.from_bytes(header, "little")
            if embedded_bytes <= 0:
                raise ValueError("MP3Stego embedded length is zero")
            if embedded_bytes > max_payload_bytes:
                raise ValueError(
                    f"MP3Stego embedded length {embedded_bytes} exceeds --max-payload-bytes"
                )
            required_bits = length_size * 8 + embedded_bytes * 8
        if required_bits is not None and len(selected) >= required_bits:
            raw_bits = selected[length_size * 8 : required_bits]
            return _HiddenPacket(
                raw=_bits_to_bytes(raw_bits),
                selected_bits=required_bits,
                embedded_bytes=embedded_bytes or 0,
                length_size=length_size,
            )
    raise ValueError("not enough selected bits")


def _bits_to_bytes(bits: Iterable[int]) -> bytes:
    out = bytearray()
    value = 0
    bit_index = 0
    for bit in bits:
        if bit:
            value |= 1 << bit_index
        bit_index += 1
        if bit_index == 8:
            out.append(value)
            value = 0
            bit_index = 0
    if bit_index:
        out.append(value)
    return bytes(out)


def _count_selected_bits(bits: list[int], password: str) -> int:
    prng = _MP3StegoPRNG(password)
    return sum(1 for _bit in bits if prng.next() == EMBED)


def _normalise_length_size(length_size: int | Literal["auto"] | str) -> int:
    if length_size == "auto":
        return 4
    value = int(length_size)
    if value not in (4, 8):
        raise ValueError("MP3Stego length size must be 4, 8 or auto")
    return value


class _MP3StegoPRNG:
    def __init__(self, password: str) -> None:
        self._password = password.encode()
        self._hash = _sha_words(self._password)
        self._block_index = 0
        self._bit_index = 0
        self._zero_count = 0

    def next(self) -> int:
        while True:
            if (self._hash[self._block_index] >> self._bit_index) & 1:
                result = EMBED
            else:
                self._zero_count += 1
                result = DONT_EMBED
            self._advance()
            if self._zero_count == COUNT_MAX:
                self._zero_count = 0
                continue
            return result

    def _advance(self) -> None:
        self._bit_index = (self._bit_index + 1) % 32
        if self._bit_index:
            return
        self._block_index = (self._block_index + 1) % 5
        if self._block_index == 0:
            state = b"".join(struct.pack("<I", word) for word in self._hash)
            self._hash = _sha_words(state + self._password)


def _sha_words(data: bytes) -> tuple[int, int, int, int, int]:
    return struct.unpack(">5I", sha1(data).digest())


def _derive_3des_key(password: str) -> bytes:
    words = _sha_words(password.encode())
    raw_hash = b"".join(struct.pack("<I", word) for word in words)
    raw_key = raw_hash[0:8] + raw_hash[6:14] + raw_hash[12:20]
    return DES3.adjust_key_parity(raw_key)


def _decrypt_mp3stego_bytes(raw: bytes, *, password: str) -> bytes:
    if len(raw) == 0 or len(raw) % 8 != 0:
        raise ValueError("MP3Stego encrypted payload length must be a non-zero multiple of 8")
    cipher = DES3.new(_derive_3des_key(password), DES3.MODE_CBC, iv=b"\x00" * 8)
    plain = cipher.decrypt(raw)
    remainder = plain[-1]
    if remainder > 7:
        raise ValueError("MP3Stego encrypted payload has invalid final block marker")
    return plain[:-8] + plain[-8 : -8 + remainder]


def _encrypt_mp3stego_bytes(payload: bytes, *, password: str = "") -> bytes:
    """Test helper matching MP3Stego's 3DES-CBC padding layout."""
    remainder = len(payload) % 8
    if remainder:
        padded = (
            payload[:-remainder] + payload[-remainder:] + bytes(7 - remainder) + bytes([remainder])
        )
    else:
        padded = payload + bytes(7) + b"\x00"
    cipher = DES3.new(_derive_3des_key(password), DES3.MODE_CBC, iv=b"\x00" * 8)
    return cipher.encrypt(padded)


def _skip_id3v2(data: bytes) -> int:
    if len(data) >= 10 and data[:3] == b"ID3":
        size = 0
        for byte in data[6:10]:
            size = (size << 7) | (byte & 0x7F)
        return 10 + size
    return 0


def _parse_header(data: bytes, offset: int) -> _Header | None:
    if offset + 4 > len(data):
        return None
    value = int.from_bytes(data[offset : offset + 4], "big")
    if (value & 0xFFE00000) != 0xFFE00000:
        return None
    version_id = (value >> 19) & 0x3
    layer = (value >> 17) & 0x3
    if version_id == 1 or layer != 1:
        return None
    protected_by_crc = ((value >> 16) & 0x1) == 0
    bitrate_index = (value >> 12) & 0xF
    sample_rate_index = (value >> 10) & 0x3
    padding = (value >> 9) & 0x1
    channel_mode_index = (value >> 6) & 0x3
    bitrate = BITRATES_LAYER3[version_id][bitrate_index]
    sample_rate = SAMPLE_RATES[version_id][sample_rate_index]
    if bitrate is None or sample_rate is None:
        return None
    if version_id == 3:
        frame_length = int((144000 * bitrate) // sample_rate + padding)
        granules = 2
    else:
        frame_length = int((72000 * bitrate) // sample_rate + padding)
        granules = 1
    if frame_length <= 4:
        return None
    channels = 1 if channel_mode_index == 3 else 2
    side_info_bytes = (
        (17 if channels == 1 else 32) if version_id == 3 else (9 if channels == 1 else 17)
    )
    side_info_offset = offset + 4 + (2 if protected_by_crc else 0)
    return _Header(
        offset=offset,
        version_id=version_id,
        version=MPEG_VERSIONS[version_id],
        bitrate_kbps=bitrate,
        sample_rate=sample_rate,
        padding=padding,
        channels=channels,
        channel_mode=CHANNEL_MODES[channel_mode_index],
        frame_length=frame_length,
        side_info_offset=side_info_offset,
        side_info_bytes=side_info_bytes,
        granules=granules,
        protected_by_crc=protected_by_crc,
    )


def _parse_side_info_lengths(side_info: bytes, header: _Header) -> list[int]:
    reader = _BitReader(side_info)
    lengths: list[int] = []
    if header.version_id == 3:
        reader.read(9)
        reader.read(5 if header.channels == 1 else 3)
        for _ch in range(header.channels):
            reader.read(4)
        scalefac_compress_bits = 4
        has_preflag = True
    else:
        reader.read(8)
        reader.read(1 if header.channels == 1 else 2)
        scalefac_compress_bits = 9
        has_preflag = False
    for _gr in range(header.granules):
        for _ch in range(header.channels):
            lengths.append(reader.read(12))
            reader.read(9)  # big_values
            reader.read(8)  # global_gain
            reader.read(scalefac_compress_bits)
            window_switching = reader.read(1)
            if window_switching:
                reader.read(2)  # block_type
                reader.read(1)  # mixed_block_flag
                reader.read(10)  # table_select[2]
                reader.read(9)  # subblock_gain[3]
            else:
                reader.read(15)  # table_select[3]
                reader.read(4)  # region0_count
                reader.read(3)  # region1_count
            if has_preflag:
                reader.read(1)
            reader.read(1)  # scalefac_scale
            reader.read(1)  # count1table_select
    return lengths


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._bit_pos = 0

    def read(self, count: int) -> int:
        if self._bit_pos + count > len(self._data) * 8:
            raise ValueError("truncated MPEG side information")
        value = 0
        for _ in range(count):
            byte = self._data[self._bit_pos // 8]
            shift = 7 - (self._bit_pos % 8)
            value = (value << 1) | ((byte >> shift) & 1)
            self._bit_pos += 1
        return value


def _iter_passwords(wordlist: Path, *, include_default: bool, encoding: str) -> Iterable[str]:
    seen: set[str] = set()
    if include_default:
        seen.add("")
        yield ""
    for line in Path(wordlist).read_text(encoding=encoding, errors="ignore").splitlines():
        password = line.rstrip("\r\n")
        if password not in seen:
            seen.add(password)
            yield password


def _resolve_mp3stego_tool(kind: str, explicit: Path | None) -> Path:
    if explicit is not None:
        return _check_executable(Path(explicit))
    env_name = "MP3STEGO_ENCODER" if kind == "encoder" else "MP3STEGO_DECODER"
    env_value = os.environ.get(env_name)
    if env_value:
        return _check_executable(Path(env_value))
    names = (
        ("Encode.exe", "encode", "mp3stego-encode")
        if kind == "encoder"
        else (
            "Decode.exe",
            "decode",
            "mp3stego-decode",
        )
    )
    for name in names:
        found = shutil.which(name)
        if found:
            return _check_executable(Path(found))
    raise ValueError(f"MP3Stego {kind} executable not found; pass --{kind} /path/to/{names[0]}")


def _check_executable(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(path)
    if not os.access(path, os.X_OK):
        raise PermissionError(f"executable bit is not set: {path}")
    return path
