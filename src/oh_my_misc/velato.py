from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MINOR_SECOND = 1
MAJOR_SECOND = 2
MINOR_THIRD = 3
MAJOR_THIRD = 4
PERFECT_FOURTH = 5
DIMINISHED_FIFTH = 6
PERFECT_FIFTH = 7
MINOR_SIXTH = 8
MAJOR_SIXTH = 9
MINOR_SEVENTH = 10
MAJOR_SEVENTH = 11

INTERVAL_NAMES = {
    0: "unison/octave",
    MINOR_SECOND: "minor second",
    MAJOR_SECOND: "major second",
    MINOR_THIRD: "minor third",
    MAJOR_THIRD: "major third",
    PERFECT_FOURTH: "perfect fourth",
    DIMINISHED_FIFTH: "diminished fifth",
    PERFECT_FIFTH: "perfect fifth",
    MINOR_SIXTH: "minor sixth",
    MAJOR_SIXTH: "major sixth",
    MINOR_SEVENTH: "minor seventh",
    MAJOR_SEVENTH: "major seventh",
}

NOTE_NAMES = ("C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B")
DIGIT_TO_INTERVAL = {0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 8, 7: 9, 8: 10, 9: 11}
INTERVAL_TO_DIGIT = {interval: digit for digit, interval in DIGIT_TO_INTERVAL.items()}


@dataclass(slots=True)
class MidiNote:
    index: int
    tick: int
    track: int
    channel: int
    number: int
    velocity: int

    @property
    def name(self) -> str:
        octave = self.number // 12 - 1
        return f"{NOTE_NAMES[self.number % 12]}{octave}"

    def to_dict(self, root: int | None = None) -> dict[str, Any]:
        interval = (self.number - root) % 12 if root is not None else None
        return {
            "index": self.index,
            "tick": self.tick,
            "track": self.track,
            "channel": self.channel,
            "number": self.number,
            "name": self.name,
            "velocity": self.velocity,
            "interval": interval,
            "interval_name": INTERVAL_NAMES.get(interval) if interval is not None else None,
        }


@dataclass(slots=True)
class VelatoExpression:
    kind: str
    text: str
    value: int | float | str | None = None
    expression_type: str = ""
    notes: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "type": self.expression_type,
            "text": self.text,
            "value": self.value,
            "notes": self.notes,
        }


@dataclass(slots=True)
class VelatoCommand:
    command: str
    start_note: int
    end_note: int
    notes: list[int] = field(default_factory=list)
    text: str = ""
    value: int | float | str | None = None
    expression: VelatoExpression | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "start_note": self.start_note,
            "end_note": self.end_note,
            "notes": self.notes,
            "text": self.text,
            "value": self.value,
            "expression": self.expression.to_dict() if self.expression else None,
            "detail": self.detail,
        }


@dataclass(slots=True)
class VelatoResult:
    operation: str
    input_path: str = "-"
    output_path: str = "-"
    output_paths: list[str] = field(default_factory=list)
    mode: str = "inspect"
    format: int | None = None
    tracks: int = 0
    ticks_per_quarter: int | None = None
    note_count: int = 0
    command_count: int = 0
    printed_text: str = ""
    generated_text: str = ""
    root_note: int | None = None
    root_name: str = ""
    written_bytes: int = 0
    notes: list[dict[str, Any]] = field(default_factory=list)
    commands: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    status: str = "success"

    @property
    def count(self) -> int:
        return self.command_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "operation": self.operation,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "output_paths": self.output_paths,
            "mode": self.mode,
            "format": self.format,
            "tracks": self.tracks,
            "ticks_per_quarter": self.ticks_per_quarter,
            "note_count": self.note_count,
            "command_count": self.command_count,
            "count": self.count,
            "printed_text": self.printed_text,
            "generated_text": self.generated_text,
            "root_note": self.root_note,
            "root_name": self.root_name,
            "written_bytes": self.written_bytes,
            "notes": self.notes,
            "commands": self.commands,
            "findings": self.findings,
        }


def inspect_velato(path: str | Path) -> VelatoResult:
    """Parse a Standard MIDI File as Velato and return note, command and print hints."""

    midi = _read_midi(path)
    notes = midi["notes"]
    commands = _parse_velato_commands(notes)
    printed = "".join(command.text for command in commands if command.command == "print")
    root = notes[0].number if notes else None
    findings = _make_findings(printed)
    return VelatoResult(
        operation="audio.velato.inspect",
        input_path=str(Path(path)),
        mode="inspect",
        format=midi["format"],
        tracks=midi["tracks"],
        ticks_per_quarter=midi["division"],
        note_count=len(notes),
        command_count=len(commands),
        printed_text=printed,
        root_note=root,
        root_name=notes[0].name if notes else "",
        notes=_note_trace(notes),
        commands=[command.to_dict() for command in commands],
        findings=findings,
    )


def decode_velato(path: str | Path, output: str | Path) -> VelatoResult:
    """Extract text produced by Velato print commands from a MIDI file."""

    result = inspect_velato(path)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = result.printed_text.encode("utf-8")
    output_path.write_bytes(data)
    result.operation = "audio.velato.decode"
    result.mode = "decode"
    result.output_path = str(output_path)
    result.output_paths = [str(output_path)]
    result.written_bytes = len(data)
    return result


def encode_velato_text(
    output: str | Path,
    text: str,
    *,
    root_note: int = 60,
    velocity: int = 80,
    duration: int = 120,
    separator: bool = True,
) -> VelatoResult:
    """Create a simple Velato MIDI program that prints *text* using char literals."""

    if not 0 <= root_note <= 115:
        raise ValueError("root_note must be in 0..115 so command intervals fit in MIDI notes")
    if not 1 <= velocity <= 127:
        raise ValueError("velocity must be in 1..127")
    if duration <= 0:
        raise ValueError("duration must be positive")
    notes = _notes_for_printing_text(text, root_note=root_note, separator=separator)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_midi_notes(output_path, notes, velocity=velocity, duration=duration)
    size = output_path.stat().st_size
    decoded = inspect_velato(output_path)
    return VelatoResult(
        operation="audio.velato.encode",
        input_path="-",
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="encode",
        format=0,
        tracks=1,
        ticks_per_quarter=480,
        note_count=decoded.note_count,
        command_count=decoded.command_count,
        printed_text=decoded.printed_text,
        generated_text=text,
        root_note=root_note,
        root_name=MidiNote(0, 0, 0, 0, root_note, velocity).name,
        written_bytes=size,
        notes=decoded.notes,
        commands=decoded.commands,
        findings=decoded.findings,
    )


def _parse_velato_commands(notes: list[MidiNote]) -> list[VelatoCommand]:
    if not notes:
        return []
    root = notes[0].number
    commands: list[VelatoCommand] = []
    index = 1
    while index < len(notes):
        start = index
        interval = _interval(notes[index], root)
        if interval == 0:
            index += 1
            continue
        if interval == MAJOR_SECOND:
            if index + 1 >= len(notes):
                commands.append(
                    VelatoCommand(
                        "root-change",
                        start,
                        len(notes) - 1,
                        [notes[index].index],
                        detail="truncated root-change command",
                    )
                )
                break
            root = notes[index + 1].number
            commands.append(
                VelatoCommand(
                    "root-change",
                    start,
                    index + 1,
                    [notes[index].index, notes[index + 1].index],
                    detail=f"new root {notes[index + 1].name}",
                )
            )
            index += 2
            continue
        if interval == MAJOR_SIXTH:
            command, index = _parse_special(notes, index + 1, root, start)
            commands.append(command)
            continue
        if interval == MINOR_SIXTH:
            command, index = _parse_declare(notes, index, root)
            commands.append(command)
            continue
        if interval == MINOR_THIRD:
            command, index = _parse_let(notes, index, root)
            commands.append(command)
            continue
        if interval == MAJOR_THIRD:
            command, index = _parse_block(notes, index, root)
            commands.append(command)
            continue
        commands.append(
            VelatoCommand(
                "unknown",
                start,
                start,
                [notes[start].index],
                detail=f"unexpected first command interval {interval}: {INTERVAL_NAMES[interval]}",
            )
        )
        index += 1
    return commands


def _parse_special(
    notes: list[MidiNote], index: int, root: int, start: int
) -> tuple[VelatoCommand, int]:
    if index >= len(notes):
        return VelatoCommand("special", start, len(notes) - 1, [notes[start].index], detail="truncated"), index
    interval = _interval(notes[index], root)
    if interval in {PERFECT_FOURTH, MAJOR_SIXTH}:
        if index + 1 < len(notes):
            end = index + 1
            return (
                VelatoCommand(
                    "input",
                    start,
                    end,
                    [notes[start].index, notes[index].index, notes[end].index],
                    text=_variable_name(notes[end]),
                    detail=f"read one char into {_variable_name(notes[end])}",
                ),
                end + 1,
            )
        return VelatoCommand("input", start, index, [notes[start].index, notes[index].index], detail="truncated"), index + 1
    if interval == PERFECT_FIFTH:
        expression, next_index = _parse_expression(notes, index + 1, root)
        printed = _expression_print_text(expression)
        end = max(index, next_index - 1)
        return (
            VelatoCommand(
                "print",
                start,
                end,
                [note.index for note in notes[start:next_index]],
                text=printed,
                value=expression.value,
                expression=expression,
                detail=f"Console.Write({expression.text})",
            ),
            next_index,
        )
    return (
        VelatoCommand(
            "special",
            start,
            index,
            [notes[start].index, notes[index].index],
            detail=f"unexpected special interval {interval}: {INTERVAL_NAMES[interval]}",
        ),
        index + 1,
    )


def _parse_declare(notes: list[MidiNote], index: int, root: int) -> tuple[VelatoCommand, int]:
    if index + 2 >= len(notes):
        return VelatoCommand("declare", index, len(notes) - 1, [notes[index].index], detail="truncated"), len(notes)
    variable = _variable_name(notes[index + 1])
    type_interval = _interval(notes[index + 2], root)
    type_name = "int" if type_interval in {MINOR_SECOND, MAJOR_SECOND} else "char" if type_interval in {MINOR_THIRD, MAJOR_THIRD} else "double" if type_interval == PERFECT_FOURTH else "unknown"
    return (
        VelatoCommand(
            "declare",
            index,
            index + 2,
            [note.index for note in notes[index : index + 3]],
            text=f"{type_name} {variable};",
            detail=f"declare {variable} as {type_name}",
        ),
        index + 3,
    )


def _parse_let(notes: list[MidiNote], index: int, root: int) -> tuple[VelatoCommand, int]:
    if index + 1 >= len(notes):
        return VelatoCommand("let", index, len(notes) - 1, [notes[index].index], detail="truncated"), len(notes)
    variable = _variable_name(notes[index + 1])
    expression, next_index = _parse_expression(notes, index + 2, root)
    return (
        VelatoCommand(
            "let",
            index,
            max(index + 1, next_index - 1),
            [note.index for note in notes[index:next_index]],
            text=f"{variable} = {expression.text};",
            value=expression.value,
            expression=expression,
            detail=f"assign {variable}",
        ),
        next_index,
    )


def _parse_block(notes: list[MidiNote], index: int, root: int) -> tuple[VelatoCommand, int]:
    if index + 1 >= len(notes):
        return VelatoCommand("block", index, len(notes) - 1, [notes[index].index], detail="truncated"), len(notes)
    second = _interval(notes[index + 1], root)
    names = {
        MAJOR_THIRD: "while",
        PERFECT_FOURTH: "end-while",
        PERFECT_FIFTH: "if",
        MAJOR_SIXTH: "else",
        MAJOR_SEVENTH: "end-if",
    }
    command = names.get(second, "block")
    return (
        VelatoCommand(
            command,
            index,
            index + 1,
            [notes[index].index, notes[index + 1].index],
            detail=f"block marker {INTERVAL_NAMES.get(second, second)}",
        ),
        index + 2,
    )


def _parse_expression(notes: list[MidiNote], index: int, root: int) -> tuple[VelatoExpression, int]:
    if index >= len(notes):
        return VelatoExpression("unknown", "<truncated>"), index
    first = _interval(notes[index], root)
    if first in {MINOR_THIRD, MAJOR_THIRD}:
        return _parse_value_expression(notes, index, root)
    if first in {MINOR_SECOND, MAJOR_SECOND}:
        return _parse_two_note_operator(
            notes,
            index,
            root,
            {
                (MINOR_SECOND, MAJOR_SECOND): ("==", "equal"),
                (MINOR_THIRD, MAJOR_THIRD): (">", "greater-than"),
                (PERFECT_FOURTH,): ("<", "less-than"),
                (DIMINISHED_FIFTH, PERFECT_FIFTH): ("!", "not"),
                (MINOR_SIXTH, MAJOR_SIXTH): ("&&", "and"),
                (MINOR_SEVENTH, MAJOR_SEVENTH): ("||", "or"),
            },
            "conditional",
        )
    if (
        first == PERFECT_FIFTH
        and index + 2 < len(notes)
        and _interval(notes[index + 1], root) == PERFECT_FIFTH
    ):
        third = _interval(notes[index + 2], root)
        math_ops = {
            MINOR_SECOND: ("-", "minus"),
            MAJOR_SECOND: ("-", "minus"),
            MINOR_THIRD: ("+", "plus"),
            MAJOR_THIRD: ("+", "plus"),
            PERFECT_FOURTH: ("/", "divide"),
            DIMINISHED_FIFTH: ("*", "multiply"),
            PERFECT_FIFTH: ("*", "multiply"),
            MINOR_SIXTH: ("%", "mod"),
            MAJOR_SIXTH: ("%", "mod"),
        }
        text, kind = math_ops.get(third, (f"<math:{third}>", "unknown"))
        return VelatoExpression(
            kind,
            text,
            expression_type="operator",
            notes=[notes[index].index, notes[index + 1].index, notes[index + 2].index],
        ), index + 3
    if (
        first in {MINOR_SIXTH, MAJOR_SIXTH}
        and index + 2 < len(notes)
        and _interval(notes[index + 1], root) in {MINOR_SIXTH, MAJOR_SIXTH}
    ):
        third = _interval(notes[index + 2], root)
        if third in {MINOR_SECOND, MAJOR_SECOND}:
            return (
                VelatoExpression(
                    "close-paren",
                    ")",
                    expression_type="group",
                    notes=[note.index for note in notes[index : index + 3]],
                ),
                index + 3,
            )
        if third in {MINOR_SIXTH, MAJOR_SIXTH}:
            return (
                VelatoExpression(
                    "open-paren",
                    "(",
                    expression_type="group",
                    notes=[note.index for note in notes[index : index + 3]],
                ),
                index + 3,
            )
    return VelatoExpression("unknown", f"<expr:{first}>", notes=[notes[index].index]), index + 1


def _parse_two_note_operator(
    notes: list[MidiNote],
    index: int,
    root: int,
    groups: dict[tuple[int, ...], tuple[str, str]],
    expression_type: str,
) -> tuple[VelatoExpression, int]:
    if index + 1 >= len(notes):
        return VelatoExpression("unknown", "<truncated>", notes=[notes[index].index]), len(notes)
    second = _interval(notes[index + 1], root)
    for intervals, (text, kind) in groups.items():
        if second in intervals:
            return (
                VelatoExpression(
                    kind,
                    text,
                    expression_type=expression_type,
                    notes=[notes[index].index, notes[index + 1].index],
                ),
                index + 2,
            )
    return VelatoExpression("unknown", f"<{expression_type}:{second}>", notes=[notes[index].index, notes[index + 1].index]), index + 2


def _parse_value_expression(
    notes: list[MidiNote], index: int, root: int
) -> tuple[VelatoExpression, int]:
    if index + 1 >= len(notes):
        return VelatoExpression("value", "<truncated>", notes=[notes[index].index]), len(notes)
    second = _interval(notes[index + 1], root)
    used = [notes[index].index, notes[index + 1].index]
    if second in {MINOR_SECOND, MAJOR_SECOND}:
        if index + 2 >= len(notes):
            return VelatoExpression("variable", "<truncated>", notes=used), len(notes)
        variable = _variable_name(notes[index + 2])
        return VelatoExpression("variable", variable, variable, "variable", used + [notes[index + 2].index]), index + 3
    if second in {MINOR_THIRD, MAJOR_THIRD}:
        digits, next_index, digit_notes = _read_digits(notes, index + 2, root)
        value = -int(digits or "0")
        return VelatoExpression("value", str(value), value, "int", used + digit_notes), next_index
    if second == PERFECT_FOURTH:
        digits, next_index, digit_notes = _read_digits(notes, index + 2, root)
        value = int(digits or "0")
        text = chr(value) if 0 <= value <= 0x10FFFF else ""
        return VelatoExpression("value", repr(text), text, "char", used + digit_notes), next_index
    if second in {DIMINISHED_FIFTH, PERFECT_FIFTH}:
        digits, next_index, digit_notes = _read_digits(notes, index + 2, root)
        value = int(digits or "0")
        return VelatoExpression("value", str(value), value, "int", used + digit_notes), next_index
    if second in {MINOR_SIXTH, MAJOR_SIXTH, MINOR_SEVENTH, MAJOR_SEVENTH}:
        whole, middle_index, whole_notes = _read_digits(notes, index + 2, root)
        fraction, next_index, fraction_notes = _read_digits(notes, middle_index, root)
        value = float(f"{whole or '0'}.{fraction or '0'}")
        if second in {MINOR_SEVENTH, MAJOR_SEVENTH}:
            value = -value
        return VelatoExpression("value", repr(value), value, "double", used + whole_notes + fraction_notes), next_index
    return VelatoExpression("value", f"<value:{second}>", notes=used), index + 2


def _read_digits(notes: list[MidiNote], index: int, root: int) -> tuple[str, int, list[int]]:
    digits: list[str] = []
    used: list[int] = []
    while index < len(notes):
        interval = _interval(notes[index], root)
        used.append(notes[index].index)
        index += 1
        if interval == PERFECT_FIFTH:
            break
        if interval == 0:
            continue
        if interval not in INTERVAL_TO_DIGIT:
            break
        digits.append(str(INTERVAL_TO_DIGIT[interval]))
    return "".join(digits), index, used


def _expression_print_text(expression: VelatoExpression) -> str:
    if expression.expression_type == "char" and isinstance(expression.value, str):
        return expression.value
    if expression.expression_type in {"int", "double"} and expression.value is not None:
        return str(expression.value)
    if expression.expression_type == "variable" and expression.value is not None:
        return str(expression.value)
    return expression.text if expression.kind != "unknown" else ""


def _variable_name(note: MidiNote) -> str:
    return note.name.replace("#", "s")


def _interval(note: MidiNote, root: int) -> int:
    return (note.number - root) % 12


def _note_trace(notes: list[MidiNote]) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    root: int | None = None
    index = 0
    while index < len(notes):
        if root is None:
            root = notes[index].number
            item = notes[index].to_dict(root)
            item["root"] = notes[index].name
            trace.append(item)
            index += 1
            continue
        item = notes[index].to_dict(root)
        trace.append(item)
        if item["interval"] == MAJOR_SECOND and index + 1 < len(notes):
            root = notes[index + 1].number
        index += 1
    return trace


def _make_findings(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lowered = text.lower()
    for marker in ("flag{", "ctf{", "{"):
        pos = lowered.find(marker)
        if pos >= 0:
            findings.append({"kind": "flag" if marker != "{" else "brace", "offset": pos, "text": text[pos : pos + 80]})
            break
    if text:
        findings.append({"kind": "printed-text", "offset": 0, "text": text[:120]})
    return findings


def _read_midi(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_bytes()
    if len(data) < 14 or data[:4] != b"MThd":
        raise ValueError("not a Standard MIDI File: missing MThd header")
    header_length = struct.unpack_from(">I", data, 4)[0]
    if header_length < 6 or len(data) < 8 + header_length:
        raise ValueError("invalid MIDI header length")
    midi_format, track_count, division = struct.unpack_from(">HHH", data, 8)
    pos = 8 + header_length
    all_notes: list[MidiNote] = []
    chosen_track_notes: list[MidiNote] = []
    for track_index in range(track_count):
        if pos + 8 > len(data) or data[pos : pos + 4] != b"MTrk":
            raise ValueError(f"missing MTrk header for track {track_index}")
        track_length = struct.unpack_from(">I", data, pos + 4)[0]
        start = pos + 8
        end = start + track_length
        if end > len(data):
            raise ValueError(f"track {track_index} extends beyond file")
        track_notes = _parse_track(data[start:end], track_index, len(all_notes))
        all_notes.extend(track_notes)
        if not chosen_track_notes and track_notes:
            chosen_track_notes = track_notes
        pos = end
    return {
        "format": midi_format,
        "tracks": track_count,
        "division": division,
        "notes": chosen_track_notes or all_notes,
    }


def _parse_track(track_data: bytes, track_index: int, start_index: int) -> list[MidiNote]:
    notes: list[MidiNote] = []
    pos = 0
    tick = 0
    running_status: int | None = None
    while pos < len(track_data):
        delta, pos = _read_varlen(track_data, pos)
        tick += delta
        if pos >= len(track_data):
            break
        status = track_data[pos]
        if status < 0x80:
            if running_status is None:
                raise ValueError(f"running status without previous status in track {track_index}")
        else:
            pos += 1
            if status in {0xF0, 0xF7}:
                length, pos = _read_varlen(track_data, pos)
                pos += length
                continue
            if status == 0xFF:
                if pos >= len(track_data):
                    raise ValueError("truncated MIDI meta event")
                pos += 1
                length, pos = _read_varlen(track_data, pos)
                pos += length
                continue
            running_status = status
        event_status = running_status if status < 0x80 else status
        if event_status is None:
            raise ValueError("missing MIDI event status")
        event_type = event_status & 0xF0
        channel = event_status & 0x0F
        data_len = 1 if event_type in {0xC0, 0xD0} else 2
        if pos + data_len > len(track_data):
            raise ValueError("truncated MIDI channel event")
        param1 = track_data[pos]
        param2 = track_data[pos + 1] if data_len == 2 else 0
        pos += data_len
        if event_type == 0x90 and param2 > 0:
            notes.append(
                MidiNote(
                    index=start_index + len(notes),
                    tick=tick,
                    track=track_index,
                    channel=channel,
                    number=param1,
                    velocity=param2,
                )
            )
    return notes


def _read_varlen(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for _ in range(4):
        if pos >= len(data):
            raise ValueError("truncated MIDI variable-length quantity")
        byte = data[pos]
        pos += 1
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            return value, pos
    raise ValueError("invalid MIDI variable-length quantity")


def _write_varlen(value: int) -> bytes:
    if value < 0:
        raise ValueError("variable-length quantity must be non-negative")
    buffer = value & 0x7F
    value >>= 7
    while value:
        buffer <<= 8
        buffer |= (value & 0x7F) | 0x80
        value >>= 7
    out = bytearray()
    while True:
        out.append(buffer & 0xFF)
        if buffer & 0x80:
            buffer >>= 8
        else:
            break
    return bytes(out)


def _notes_for_printing_text(text: str, *, root_note: int, separator: bool) -> list[int]:
    notes = [root_note]
    for char in text:
        notes.extend(
            [
                root_note + MAJOR_SIXTH,
                root_note + PERFECT_FIFTH,
                root_note + MAJOR_THIRD,
                root_note + PERFECT_FOURTH,
            ]
        )
        for digit in str(ord(char)):
            notes.append(root_note + DIGIT_TO_INTERVAL[int(digit)])
        notes.append(root_note + PERFECT_FIFTH)
        if separator:
            notes.append(root_note)
    return notes


def _write_midi_notes(path: Path, notes: list[int], *, velocity: int, duration: int) -> None:
    events = bytearray()
    for number in notes:
        if not 0 <= number <= 127:
            raise ValueError(f"MIDI note {number} is outside 0..127")
        events += _write_varlen(0)
        events += bytes([0x90, number, velocity])
        events += _write_varlen(duration)
        events += bytes([0x80, number, 0])
    events += b"\x00\xff\x2f\x00"
    header = b"MThd" + struct.pack(">IHHH", 6, 0, 1, 480)
    track = b"MTrk" + struct.pack(">I", len(events)) + bytes(events)
    path.write_bytes(header + track)
