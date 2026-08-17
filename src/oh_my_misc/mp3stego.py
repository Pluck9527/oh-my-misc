from __future__ import annotations

import gzip
import struct
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


@dataclass(frozen=True)
class _ParsedMP3Frame:
    frame: MP3StegoFrame
    header: _Header
    length_lsb_bit_offsets: list[int]


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
    length_size: int | Literal["auto"] = 4,
) -> MP3StegoResult:
    """Embed MP3Stego-compatible bits by patching Layer III side-info parity.

    For an MP3 input, the function keeps the carrier bytes and flips only the
    least significant bit of selected ``part2_3_length`` fields.  For the legacy
    CLI shape that passes a WAV input, a deterministic MPEG Layer III frame
    carrier is generated locally so tests and CTF fixtures no longer need
    MP3Stego's external ``Encode.exe``.
    """

    _check_file(input_path, "MP3/WAV 载体")
    _check_file(payload_path, "载荷文件")
    _ = encoder  # Accepted for backward CLI compatibility; native mode never calls it.
    length_size = _normalise_length_size(length_size)
    payload = Path(payload_path).read_bytes()
    raw_payload = _compress_encrypt_mp3stego_payload(payload, password=password)
    if len(raw_payload) >= 1 << (length_size * 8):
        raise ValueError("MP3Stego 嵌入密文长度超过长度头可表达范围")

    carrier = bytearray(Path(input_path).read_bytes())
    try:
        parsed_frames = _parse_mp3_frames_from_bytes(bytes(carrier))
        generated_carrier = False
        hidden_source = _StegoOpenEmbeddedText(raw_payload, password=password, length_size=length_size)
        selected_bits = _embed_packet_bits_in_frames(carrier, parsed_frames, hidden_source)
    except ValueError:
        if not _looks_like_wav_container(carrier):
            raise
        carrier_bytes, selected_bits = _build_synthetic_mp3stego_carrier(
            raw_payload,
            password=password,
            length_size=length_size,
        )
        carrier = bytearray(carrier_bytes)
        parsed_frames = _parse_mp3_frames_from_bytes(bytes(carrier))
        generated_carrier = True

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(carrier)
    frames = parse_mp3_frames(output_path)
    if not output_path.exists():
        raise ValueError("MP3Stego native encoder finished without producing the requested MP3")
    candidate_bits = sum(len(frame.hidden_bits) for frame in frames)
    return MP3StegoResult(
        operation="audio.mp3stego.encode-native",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="encode-native-synthetic" if generated_carrier else "encode-native",
        password_used=bool(password),
        found_password=password if password else "",
        length_size=length_size,
        frames=len(frames),
        candidate_bits=candidate_bits,
        selected_bits=selected_bits,
        embedded_bytes=len(raw_payload),
        payload_bytes=len(payload),
        raw_bytes=len(raw_payload),
        decoded=False,
        decrypted=False,
        uncompressed=False,
        attempts=1,
        executable="python",
        command=["native-mp3stego-side-info-parity"],
        stdout="",
        stderr="",
        returncode=0,
        written_bytes=output_path.stat().st_size,
        frame_entries=[frame.to_dict() for frame in frames[:10]],
    )


def parse_mp3_frames(input_path: Path) -> list[MP3StegoFrame]:
    data = Path(input_path).read_bytes()
    return [item.frame for item in _parse_mp3_frames_from_bytes(data)]


def _parse_mp3_frames_from_bytes(data: bytes) -> list[_ParsedMP3Frame]:
    frames: list[MP3StegoFrame] = []
    parsed: list[_ParsedMP3Frame] = []
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
            fields = _parse_side_info_length_fields(side_info, header)
        except ValueError:
            pos += 1
            continue
        lengths = [field[0] for field in fields]
        bits = [value & 1 for value in lengths]
        frame = MP3StegoFrame(
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
        frames.append(frame)
        parsed.append(
            _ParsedMP3Frame(
                frame=frame,
                header=header,
                length_lsb_bit_offsets=[field[1] for field in fields],
            )
        )
        pos = header.offset + header.frame_length
    if not frames:
        raise ValueError("no MPEG Layer III frames found")
    return parsed


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
    sink = _StegoCreateEmbeddedText(
        password=password,
        length_size=length_size,
        max_payload_bytes=max_payload_bytes,
    )
    for bit in bits:
        sink.save_hidden_bit(bit)
        if sink.finished:
            return sink.flush()
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
    return [value for value, _offset in _parse_side_info_length_fields(side_info, header)]


def _parse_side_info_length_fields(side_info: bytes, header: _Header) -> list[tuple[int, int]]:
    reader = _BitReader(side_info)
    fields: list[tuple[int, int]] = []
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
            start = reader.bit_pos
            fields.append((reader.read(12), start + 11))
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
    return fields


def _compress_encrypt_mp3stego_payload(payload: bytes, *, password: str) -> bytes:
    """Python equivalent of StegoLib CompressEncryptFile(..., bCompEnc=1)."""

    return _encrypt_mp3stego_bytes(gzip.compress(payload, mtime=0), password=password)


def _bytes_to_lsb_bits(data: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


class _StegoOpenEmbeddedText:
    """Stateful Python port of StegoOpenEmbeddedText + StegoGetNextBit.

    The C implementation first hides sizeof(size_t) bytes containing the length
    of the compressed/encrypted payload, then streams the payload bytes LSB
    first.  Each carrier opportunity is gated by GetPseudoRandomBit(NEXT), and
    once all data bits are consumed StegoGetNextBit returns DO_NOTHING without
    advancing the PRNG.
    """

    def __init__(self, hidden_data: bytes, *, password: str, length_size: int) -> None:
        self._bits = _bytes_to_lsb_bits(len(hidden_data).to_bytes(length_size, "little"))
        self._bits.extend(_bytes_to_lsb_bits(hidden_data))
        self._prng = _MP3StegoPRNG(password)
        self._bit_index = 0

    @property
    def finished(self) -> bool:
        return self._bit_index >= len(self._bits)

    @property
    def embedded_bits(self) -> int:
        return self._bit_index

    @property
    def total_bits(self) -> int:
        return len(self._bits)

    def get_next_bit(self) -> int:
        if self.finished:
            return DO_NOTHING
        if self._prng.next() != EMBED:
            return DO_NOTHING
        bit = self._bits[self._bit_index]
        self._bit_index += 1
        return bit


class _StegoCreateEmbeddedText:
    """Stateful Python port of StegoCreateEmbeddedText + SaveHiddenBit."""

    def __init__(self, *, password: str, length_size: int, max_payload_bytes: int) -> None:
        self._prng = _MP3StegoPRNG(password)
        self._length_size = length_size
        self._max_payload_bytes = max_payload_bytes
        self._header_bits: list[int] = []
        self._body_bits: list[int] = []
        self._embedded_bytes: int | None = None
        self._finished = False

    @property
    def finished(self) -> bool:
        return self._finished

    def save_hidden_bit(self, bit: int) -> None:
        if self._finished:
            return
        if self._prng.next() != EMBED:
            return
        if self._embedded_bytes is None:
            self._header_bits.append(bit & 1)
            if len(self._header_bits) == self._length_size * 8:
                header = _bits_to_bytes(self._header_bits)
                self._embedded_bytes = int.from_bytes(header, "little")
                if self._embedded_bytes <= 0:
                    raise ValueError("MP3Stego embedded length is zero")
                if self._embedded_bytes > self._max_payload_bytes:
                    raise ValueError(
                        f"MP3Stego embedded length {self._embedded_bytes} "
                        "exceeds --max-payload-bytes"
                    )
            return
        self._body_bits.append(bit & 1)
        if len(self._body_bits) == self._embedded_bytes * 8:
            self._finished = True

    def flush(self) -> _HiddenPacket:
        if not self._finished or self._embedded_bytes is None:
            raise ValueError("not enough selected bits")
        return _HiddenPacket(
            raw=_bits_to_bytes(self._body_bits),
            selected_bits=self._length_size * 8 + self._embedded_bytes * 8,
            embedded_bytes=self._embedded_bytes,
            length_size=self._length_size,
        )


def _embed_packet_bits_in_frames(
    carrier: bytearray,
    frames: list[_ParsedMP3Frame],
    hidden_source: _StegoOpenEmbeddedText,
) -> int:
    for parsed in frames:
        base_bit_offset = parsed.header.side_info_offset * 8
        for bit_offset in parsed.length_lsb_bit_offsets:
            hidden_bit = hidden_source.get_next_bit()
            if hidden_bit == DO_NOTHING:
                continue
            _set_stream_bit(carrier, base_bit_offset + bit_offset, hidden_bit)
            if hidden_source.finished:
                return hidden_source.embedded_bits
    if not hidden_source.finished:
        raise ValueError(
            "MP3 carrier capacity too small for MP3Stego payload: "
            f"selected {hidden_source.embedded_bits}/{hidden_source.total_bits} bits"
        )
    return hidden_source.embedded_bits


def _set_stream_bit(data: bytearray, bit_offset: int, bit: int) -> None:
    byte_index = bit_offset // 8
    shift = 7 - (bit_offset % 8)
    mask = 1 << shift
    if bit:
        data[byte_index] |= mask
    else:
        data[byte_index] &= ~mask


def _looks_like_wav_container(data: bytes | bytearray) -> bool:
    return len(data) >= 12 and bytes(data[:4]) == b"RIFF" and bytes(data[8:12]) == b"WAVE"


def _build_synthetic_mp3stego_carrier(
    hidden_data: bytes,
    *,
    password: str,
    length_size: int,
) -> tuple[bytes, int]:
    hidden_source = _StegoOpenEmbeddedText(hidden_data, password=password, length_size=length_size)
    frames: list[bytes] = []
    while not hidden_source.finished:
        hidden_bits: list[int] = []
        for _ in range(2):
            hidden_bit = hidden_source.get_next_bit()
            hidden_bits.append(0 if hidden_bit == DO_NOTHING else hidden_bit)
        frames.append(_synthetic_mpeg1_mono_frame(hidden_bits))
    return b"".join(frames), hidden_source.embedded_bits


def _synthetic_mpeg1_mono_frame(hidden_bits: list[int]) -> bytes:
    header = bytes([0xFF, 0xFB, 0xB0, 0xC0])  # MPEG1 Layer III, 192 kbps, 44100 Hz, mono
    side_info = _synthetic_mpeg1_mono_side_info([1 if bit else 0 for bit in hidden_bits])
    frame_length = 626
    return header + side_info + bytes(frame_length - 4 - len(side_info))


def _synthetic_mpeg1_mono_side_info(part2_3_lengths: list[int]) -> bytes:
    if len(part2_3_lengths) != 2:
        raise ValueError("synthetic MP3Stego frame expects two MPEG1 mono granule bits")
    bits: list[int] = []
    bits.extend(_msb_bits(0, 9))  # main_data_begin
    bits.extend(_msb_bits(0, 5))  # private_bits, mono MPEG1
    bits.extend(_msb_bits(0, 4))  # scfsi
    for value in part2_3_lengths:
        bits.extend(_msb_bits(value, 12))
        bits.extend(_msb_bits(0, 9))  # big_values
        bits.extend(_msb_bits(210, 8))  # global_gain
        bits.extend(_msb_bits(0, 4))  # scalefac_compress
        bits.extend(_msb_bits(0, 1))  # window_switching_flag
        bits.extend(_msb_bits(0, 15))  # table_select
        bits.extend(_msb_bits(0, 4))  # region0_count
        bits.extend(_msb_bits(0, 3))  # region1_count
        bits.extend(_msb_bits(0, 1))  # preflag
        bits.extend(_msb_bits(0, 1))  # scalefac_scale
        bits.extend(_msb_bits(0, 1))  # count1table_select
    return _pack_msb_bits(bits)[:17]


def _msb_bits(value: int, count: int) -> list[int]:
    return [(value >> (count - 1 - bit)) & 1 for bit in range(count)]


def _pack_msb_bits(bits: list[int]) -> bytes:
    padded = bits + [0] * ((8 - len(bits) % 8) % 8)
    out = bytearray()
    for index in range(0, len(padded), 8):
        value = 0
        for bit in padded[index : index + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._bit_pos = 0

    @property
    def bit_pos(self) -> int:
        return self._bit_pos

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


def _check_file(path: Path, label: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
