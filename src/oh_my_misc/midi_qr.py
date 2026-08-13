from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Literal

import numpy as np
from PIL import Image

SourceKind = Literal["auto", "midi", "log"]
EventType = Literal["note_on", "note_off"]

DEFAULT_PPQ = 480
DEFAULT_BPM = 120.0
DEFAULT_MIN_DURATION_MS = 120.0
DEFAULT_ROW_GAP_SECONDS = 0.01
DEFAULT_CELL_SIZE = 20


@dataclass(frozen=True)
class MidiEvent:
    timestamp: float
    event_type: EventType
    note: int
    velocity: int
    channel: int = 0
    status: int = 0x90
    tick: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MidiQrResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    source: str
    rows: int
    columns: int
    note_count: int
    note_on_count: int
    event_count: int
    cell_size: int
    row_gap_seconds: float
    bpm: float
    ppq: int
    midi_output_path: str
    written_bytes: int
    midi_written_bytes: int
    entries: list[dict[str, Any]]
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _RawMidiEvent:
    tick: int
    event_type: EventType
    note: int
    velocity: int
    channel: int
    status: int


@dataclass(frozen=True)
class _Division:
    raw: int

    @property
    def ticks_per_beat(self) -> int:
        return self.raw if not self.is_smpte else 0

    @property
    def is_smpte(self) -> bool:
        return bool(self.raw & 0x8000)

    @property
    def seconds_per_tick(self) -> float:
        if not self.is_smpte:
            raise ValueError("seconds_per_tick 只适用于 SMPTE division")
        fps_byte = (self.raw >> 8) & 0xFF
        signed_fps = fps_byte - 256 if fps_byte >= 0x80 else fps_byte
        fps = abs(signed_fps)
        ticks_per_frame = self.raw & 0xFF
        if fps <= 0 or ticks_per_frame <= 0:
            raise ValueError("MIDI SMPTE division 无效")
        return 1.0 / (fps * ticks_per_frame)


def render_midi_qr(
    input_path: Path,
    output_path: Path,
    *,
    source: SourceKind = "auto",
    row_gap_seconds: float = DEFAULT_ROW_GAP_SECONDS,
    cell_size: int = DEFAULT_CELL_SIZE,
    invert: bool = False,
    midi_output_path: Path | None = None,
    ppq: int = DEFAULT_PPQ,
    bpm: float = DEFAULT_BPM,
    min_duration_ms: float = DEFAULT_MIN_DURATION_MS,
) -> MidiQrResult:
    """Render NOTE ON groups from a MIDI file or timestamp/hex MIDI log as a QR-like grid."""

    input_path = Path(input_path)
    output_path = Path(output_path)
    if row_gap_seconds < 0:
        raise ValueError("row-gap 必须大于等于 0")
    if cell_size <= 0:
        raise ValueError("cell-size 必须大于 0")
    if ppq <= 0:
        raise ValueError("ppq 必须大于 0")
    if bpm <= 0:
        raise ValueError("bpm 必须大于 0")
    if min_duration_ms < 0:
        raise ValueError("min-duration-ms 必须大于等于 0")

    events, source_used = load_midi_events(input_path, source=source)
    rows = group_note_rows(events, row_gap_seconds=row_gap_seconds)
    matrix, notes = render_note_matrix(rows)
    written = save_note_matrix_png(matrix, output_path, cell_size=cell_size, invert=invert)

    midi_written = 0
    midi_output_text = ""
    output_paths = [str(output_path)]
    if midi_output_path is not None:
        midi_output_path = Path(midi_output_path)
        midi_written = write_midi_from_events(
            events,
            midi_output_path,
            ppq=ppq,
            bpm=bpm,
            min_duration_ms=min_duration_ms,
        )
        midi_output_text = str(midi_output_path)
        output_paths.append(midi_output_text)

    note_on_count = sum(1 for event in events if event.event_type == "note_on")
    entries = [
        {"kind": "note-map", "note": note, "column": column} for column, note in enumerate(notes)
    ]
    entries.extend(
        {
            "kind": "row",
            "row": index,
            "notes": sorted(set(row)),
            "count": len(set(row)),
        }
        for index, row in enumerate(rows[:50])
    )
    return MidiQrResult(
        operation="audio.midi-qr.render",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=output_paths,
        mode="render",
        source=source_used,
        rows=int(matrix.shape[0]),
        columns=int(matrix.shape[1]),
        note_count=len(notes),
        note_on_count=note_on_count,
        event_count=len(events),
        cell_size=cell_size,
        row_gap_seconds=row_gap_seconds,
        bpm=bpm,
        ppq=ppq,
        midi_output_path=midi_output_text,
        written_bytes=written,
        midi_written_bytes=midi_written,
        entries=entries,
        count=1,
    )


def load_midi_events(
    input_path: Path, *, source: SourceKind = "auto"
) -> tuple[list[MidiEvent], str]:
    input_path = Path(input_path)
    if source not in {"auto", "midi", "log"}:
        raise ValueError(f"未知 MIDI QR 来源：{source}")
    if source == "auto":
        with input_path.open("rb") as handle:
            header = handle.read(4)
        source = "midi" if header == b"MThd" else "log"
    if source == "midi":
        return parse_midi_file(input_path), "midi"
    return parse_midi_hex_log(input_path), "log"


def parse_midi_hex_log(input_path: Path) -> list[MidiEvent]:
    """Parse lines like ``1722159321.608646000\t904064`` into note events."""

    input_path = Path(input_path)
    events: list[MidiEvent] = []
    for line_no, raw_line in enumerate(input_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            raise ValueError(f"{input_path}:{line_no}: 需要 timestamp 和十六进制 MIDI 消息")
        try:
            timestamp = float(parts[0])
        except ValueError as exc:
            raise ValueError(f"{input_path}:{line_no}: timestamp 无效：{parts[0]!r}") from exc
        hex_text = "".join(
            part[2:] if part.lower().startswith("0x") else part for part in parts[1:]
        )
        try:
            message = bytes.fromhex(hex_text)
        except ValueError as exc:
            raise ValueError(
                f"{input_path}:{line_no}: 十六进制 MIDI 消息无效：{hex_text!r}"
            ) from exc
        if not message:
            continue
        status = message[0]
        message_type = status & 0xF0
        channel = status & 0x0F
        if message_type not in {0x80, 0x90}:
            continue
        if len(message) < 3:
            raise ValueError(f"{input_path}:{line_no}: NOTE 消息至少需要 3 字节")
        note = message[1]
        velocity = message[2]
        if note > 127 or velocity > 127:
            raise ValueError(f"{input_path}:{line_no}: MIDI note/velocity 超出 0..127")
        if message_type == 0x90 and velocity > 0:
            event_type: EventType = "note_on"
        else:
            event_type = "note_off"
        events.append(
            MidiEvent(
                timestamp=timestamp,
                event_type=event_type,
                note=note,
                velocity=velocity,
                channel=channel,
                status=status,
                tick=None,
            )
        )
    if not events:
        raise ValueError("没有解析到 MIDI NOTE 事件")
    return sorted(
        events, key=lambda event: (event.timestamp, event.event_type != "note_on", event.note)
    )


def parse_midi_file(input_path: Path) -> list[MidiEvent]:
    input_path = Path(input_path)
    data = input_path.read_bytes()
    if len(data) < 14 or data[:4] != b"MThd":
        raise ValueError("不是标准 MIDI 文件（缺少 MThd）")
    header_length = struct.unpack_from(">I", data, 4)[0]
    if header_length < 6 or len(data) < 8 + header_length:
        raise ValueError("MIDI 头部长度无效")
    _format_type, track_count, raw_division = struct.unpack_from(">HHH", data, 8)
    division = _Division(raw_division)
    offset = 8 + header_length
    raw_events: list[_RawMidiEvent] = []
    tempo_changes: list[tuple[int, int]] = [(0, 500_000)]
    tracks_seen = 0
    while offset + 8 <= len(data) and tracks_seen < track_count:
        chunk_id = data[offset : offset + 4]
        chunk_size = struct.unpack_from(">I", data, offset + 4)[0]
        offset += 8
        chunk = data[offset : offset + chunk_size]
        offset += chunk_size
        if chunk_id != b"MTrk":
            continue
        tracks_seen += 1
        track_events, track_tempos = _parse_track_chunk(chunk)
        raw_events.extend(track_events)
        tempo_changes.extend(track_tempos)
    if tracks_seen == 0:
        raise ValueError("MIDI 文件没有 MTrk 轨道")
    if not raw_events:
        raise ValueError("MIDI 文件没有 NOTE ON/OFF 事件")

    tempo_map = _normalise_tempo_map(tempo_changes)
    events = [
        MidiEvent(
            timestamp=_tick_to_seconds(event.tick, division, tempo_map),
            event_type=event.event_type,
            note=event.note,
            velocity=event.velocity,
            channel=event.channel,
            status=event.status,
            tick=event.tick,
        )
        for event in raw_events
    ]
    return sorted(
        events, key=lambda event: (event.timestamp, event.event_type != "note_on", event.note)
    )


def group_note_rows(
    events: list[MidiEvent], *, row_gap_seconds: float = DEFAULT_ROW_GAP_SECONDS
) -> list[list[int]]:
    if row_gap_seconds < 0:
        raise ValueError("row-gap 必须大于等于 0")
    note_on_events = [event for event in events if event.event_type == "note_on"]
    if not note_on_events:
        raise ValueError("没有 NOTE ON 事件，不能生成二维码矩阵")
    rows: list[list[int]] = []
    current: list[int] = []
    previous_ts: float | None = None
    for event in sorted(note_on_events, key=lambda item: (item.timestamp, item.note)):
        if previous_ts is not None and event.timestamp - previous_ts > row_gap_seconds:
            if current:
                rows.append(current)
            current = []
        current.append(event.note)
        previous_ts = event.timestamp
    if current:
        rows.append(current)
    return rows


def render_note_matrix(rows: list[list[int]]) -> tuple[np.ndarray, list[int]]:
    notes = sorted({note for row in rows for note in row})
    if not rows or not notes:
        raise ValueError("没有可渲染的 MIDI note 行")
    note_to_column = {note: column for column, note in enumerate(notes)}
    matrix = np.zeros((len(rows), len(notes)), dtype=np.uint8)
    for row_index, row in enumerate(rows):
        for note in row:
            matrix[row_index, note_to_column[note]] = 1
    return matrix, notes


def save_note_matrix_png(
    matrix: np.ndarray,
    output_path: Path,
    *,
    cell_size: int = DEFAULT_CELL_SIZE,
    invert: bool = False,
) -> int:
    output_path = Path(output_path)
    if matrix.ndim != 2 or matrix.size == 0:
        raise ValueError("矩阵为空，不能保存 PNG")
    if cell_size <= 0:
        raise ValueError("cell-size 必须大于 0")
    foreground = 255 if invert else 0
    background = 0 if invert else 255
    pixels = np.where(matrix > 0, foreground, background).astype("uint8")
    image = Image.fromarray(pixels)
    height, width = matrix.shape
    image = image.resize((width * cell_size, height * cell_size), Image.Resampling.NEAREST)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)
    return output_path.stat().st_size


def write_midi_from_events(
    events: list[MidiEvent],
    output_path: Path,
    *,
    ppq: int = DEFAULT_PPQ,
    bpm: float = DEFAULT_BPM,
    min_duration_ms: float = DEFAULT_MIN_DURATION_MS,
) -> int:
    if ppq <= 0:
        raise ValueError("ppq 必须大于 0")
    if bpm <= 0:
        raise ValueError("bpm 必须大于 0")
    if not events:
        raise ValueError("没有 MIDI 事件可写入")
    output_path = Path(output_path)
    tempo_us = round(60_000_000.0 / bpm)
    processed = enforce_min_note_duration(events, min_duration_ms=min_duration_ms)
    start_time = min(event.timestamp for event in processed)
    track = bytearray()
    track.extend(b"\x00\xff\x51\x03")
    track.extend(tempo_us.to_bytes(3, "big"))
    previous_tick = 0
    for event in sorted(
        processed, key=lambda item: (item.timestamp, item.event_type != "note_off", item.note)
    ):
        relative = max(0.0, event.timestamp - start_time)
        absolute_tick = round(relative * ppq * 1_000_000.0 / tempo_us)
        delta = max(0, absolute_tick - previous_tick)
        track.extend(_encode_varlen(delta))
        message_type = 0x90 if event.event_type == "note_on" else 0x80
        status = message_type | (event.channel & 0x0F)
        track.extend(bytes((status, event.note & 0x7F, event.velocity & 0x7F)))
        previous_tick = absolute_tick
    track.extend(b"\x00\xff\x2f\x00")
    payload = bytearray()
    payload.extend(b"MThd")
    payload.extend(struct.pack(">IHHH", 6, 0, 1, ppq))
    payload.extend(b"MTrk")
    payload.extend(struct.pack(">I", len(track)))
    payload.extend(track)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return output_path.stat().st_size


def enforce_min_note_duration(
    events: list[MidiEvent], *, min_duration_ms: float = DEFAULT_MIN_DURATION_MS
) -> list[MidiEvent]:
    if min_duration_ms < 0:
        raise ValueError("min-duration-ms 必须大于等于 0")
    min_seconds = min_duration_ms / 1000.0
    active: dict[tuple[int, int], MidiEvent] = {}
    processed: list[MidiEvent] = []
    ordered = sorted(
        events, key=lambda event: (event.timestamp, event.event_type != "note_on", event.note)
    )
    for event in ordered:
        key = (event.channel, event.note)
        if event.event_type == "note_on":
            active[key] = event
            processed.append(event)
            continue
        start = active.pop(key, None)
        if start is not None:
            min_end = start.timestamp + min_seconds
            if event.timestamp < min_end:
                event = replace(event, timestamp=min_end)
        processed.append(event)
    for event in active.values():
        processed.append(
            MidiEvent(
                timestamp=event.timestamp + min_seconds,
                event_type="note_off",
                note=event.note,
                velocity=0,
                channel=event.channel,
                status=0x80 | (event.channel & 0x0F),
                tick=None,
            )
        )
    return sorted(
        processed, key=lambda event: (event.timestamp, event.event_type != "note_off", event.note)
    )


def _parse_track_chunk(chunk: bytes) -> tuple[list[_RawMidiEvent], list[tuple[int, int]]]:
    offset = 0
    tick = 0
    running_status: int | None = None
    events: list[_RawMidiEvent] = []
    tempos: list[tuple[int, int]] = []
    while offset < len(chunk):
        delta, offset = _read_varlen(chunk, offset)
        tick += delta
        if offset >= len(chunk):
            break
        first = chunk[offset]
        if first & 0x80:
            status = first
            offset += 1
            if status < 0xF0:
                running_status = status
            else:
                running_status = None
        else:
            if running_status is None:
                raise ValueError("MIDI running status 缺少前置 status")
            status = running_status

        if status == 0xFF:
            if offset >= len(chunk):
                raise ValueError("MIDI meta event 截断")
            meta_type = chunk[offset]
            offset += 1
            length, offset = _read_varlen(chunk, offset)
            payload = chunk[offset : offset + length]
            if len(payload) != length:
                raise ValueError("MIDI meta event payload 截断")
            offset += length
            if meta_type == 0x51 and length == 3:
                tempos.append((tick, int.from_bytes(payload, "big")))
            if meta_type == 0x2F:
                break
            continue
        if status in {0xF0, 0xF7}:
            length, offset = _read_varlen(chunk, offset)
            offset += length
            if offset > len(chunk):
                raise ValueError("MIDI SysEx event 截断")
            continue
        data_len = _channel_data_length(status)
        if offset + data_len > len(chunk):
            raise ValueError("MIDI channel message 截断")
        payload = chunk[offset : offset + data_len]
        offset += data_len
        message_type = status & 0xF0
        channel = status & 0x0F
        if message_type in {0x80, 0x90}:
            note = payload[0]
            velocity = payload[1]
            event_type: EventType = (
                "note_on" if message_type == 0x90 and velocity > 0 else "note_off"
            )
            events.append(
                _RawMidiEvent(
                    tick=tick,
                    event_type=event_type,
                    note=note,
                    velocity=velocity,
                    channel=channel,
                    status=status,
                )
            )
    return events, tempos


def _channel_data_length(status: int) -> int:
    message_type = status & 0xF0
    if message_type in {0x80, 0x90, 0xA0, 0xB0, 0xE0}:
        return 2
    if message_type in {0xC0, 0xD0}:
        return 1
    raise ValueError(f"不支持的 MIDI status：0x{status:02x}")


def _read_varlen(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for _ in range(4):
        if offset >= len(data):
            raise ValueError("MIDI varlen 截断")
        byte = data[offset]
        offset += 1
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            return value, offset
    raise ValueError("MIDI varlen 超过 4 字节")


def _encode_varlen(value: int) -> bytes:
    if value < 0:
        raise ValueError("MIDI varlen 不能为负数")
    buffer = value & 0x7F
    value >>= 7
    parts = [buffer]
    while value:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(parts))


def _normalise_tempo_map(tempo_changes: list[tuple[int, int]]) -> list[tuple[int, int]]:
    tempos: dict[int, int] = {0: 500_000}
    for tick, tempo in tempo_changes:
        if tempo > 0:
            tempos[tick] = tempo
    return sorted(tempos.items())


def _tick_to_seconds(tick: int, division: _Division, tempo_map: list[tuple[int, int]]) -> float:
    if division.is_smpte:
        return tick * division.seconds_per_tick
    ticks_per_beat = division.ticks_per_beat
    if ticks_per_beat <= 0:
        raise ValueError("MIDI PPQ division 无效")
    seconds = 0.0
    previous_tick = 0
    active_tempo = 500_000
    for tempo_tick, tempo in tempo_map:
        if tempo_tick <= previous_tick:
            active_tempo = tempo
            continue
        if tempo_tick >= tick:
            break
        seconds += (tempo_tick - previous_tick) * active_tempo / 1_000_000.0 / ticks_per_beat
        previous_tick = tempo_tick
        active_tempo = tempo
    seconds += (tick - previous_tick) * active_tempo / 1_000_000.0 / ticks_per_beat
    return seconds
