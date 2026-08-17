from __future__ import annotations

import gzip
import json
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.mp3stego import (
    DO_NOTHING,
    _encrypt_mp3stego_bytes,
    _MP3StegoPRNG,
    _StegoCreateEmbeddedText,
    _StegoOpenEmbeddedText,
    decode_mp3stego_payload,
    encode_mp3stego,
    extract_mp3stego,
    inspect_mp3stego,
    parse_mp3_frames,
)


def _bits(value: int, count: int) -> list[int]:
    return [(value >> (count - 1 - bit)) & 1 for bit in range(count)]


def _pack_bits(bits: list[int]) -> bytes:
    padded = bits + [0] * ((8 - len(bits) % 8) % 8)
    out = bytearray()
    for index in range(0, len(padded), 8):
        value = 0
        for bit in padded[index : index + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _side_info(part2_3_lengths: list[int]) -> bytes:
    bits: list[int] = []
    bits.extend(_bits(0, 9))  # main_data_begin
    bits.extend(_bits(0, 5))  # private_bits, mono MPEG1
    bits.extend(_bits(0, 4))  # scfsi
    for gr in range(2):
        value = part2_3_lengths[gr]
        bits.extend(_bits(value, 12))
        bits.extend(_bits(0, 9))  # big_values
        bits.extend(_bits(210, 8))  # global_gain
        bits.extend(_bits(0, 4))  # scalefac_compress
        bits.extend(_bits(0, 1))  # window_switching_flag
        bits.extend(_bits(0, 15))  # table_select
        bits.extend(_bits(0, 4))  # region0_count
        bits.extend(_bits(0, 3))  # region1_count
        bits.extend(_bits(0, 1))  # preflag
        bits.extend(_bits(0, 1))  # scalefac_scale
        bits.extend(_bits(0, 1))  # count1table_select
    return _pack_bits(bits)[:17]


def _mp3_frame(hidden_bits: list[int] | tuple[int, int]) -> bytes:
    header = bytes([0xFF, 0xFB, 0xB0, 0xC0])  # MPEG1 Layer III, 192kbps, 44100Hz, mono
    side_info = _side_info([1 if bit else 0 for bit in hidden_bits])
    frame_length = 626
    return header + side_info + bytes(frame_length - 4 - len(side_info))


def _payload_bits_for_password(raw: bytes, password: str) -> list[int]:
    data = len(raw).to_bytes(4, "little") + raw
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


def _mp3stego_sample(path: Path, payload: bytes, password: str = "") -> bytes:
    compressed = gzip.compress(payload)
    encrypted = _encrypt_mp3stego_bytes(compressed, password=password)
    payload_bits = _payload_bits_for_password(encrypted, password)
    prng = _MP3StegoPRNG(password)
    frames: list[bytes] = []
    payload_index = 0
    while payload_index < len(payload_bits):
        frame_bits: list[int] = []
        for _ in range(2):
            if payload_index < len(payload_bits) and prng.next() == 1:
                bit = payload_bits[payload_index]
                payload_index += 1
            else:
                bit = 0
            frame_bits.append(bit)
        frames.append(_mp3_frame(frame_bits))
    path.write_bytes(b"".join(frames))
    return encrypted


def test_mp3stego_parse_frames_extracts_part2_3_parity(tmp_path: Path) -> None:
    sample = tmp_path / "sample.mp3"
    sample.write_bytes(_mp3_frame([1, 0]) + _mp3_frame([0, 1]))

    frames = parse_mp3_frames(sample)

    assert len(frames) == 2
    assert frames[0].hidden_bits == [1, 0]
    assert frames[1].hidden_bits == [0, 1]
    assert frames[0].version == "1"
    assert frames[0].frame_length == 626


def test_mp3stego_native_extract_empty_password(tmp_path: Path) -> None:
    sample = tmp_path / "sample.mp3"
    output = tmp_path / "hidden.txt"
    encrypted = _mp3stego_sample(sample, b"flag{mp3stego-empty}\n", password="")

    result = extract_mp3stego(sample, output, password="")

    assert result.operation == "audio.mp3stego.extract"
    assert result.embedded_bytes == len(encrypted)
    assert result.payload_bytes == len(b"flag{mp3stego-empty}\n")
    assert output.read_bytes() == b"flag{mp3stego-empty}\n"


def test_mp3stego_native_extract_with_password_and_inspect(tmp_path: Path) -> None:
    sample = tmp_path / "sample.mp3"
    output = tmp_path / "hidden.txt"
    encrypted = _mp3stego_sample(sample, b"flag{mp3stego-pass}", password="Canon")

    inspect_result = inspect_mp3stego(sample, password="Canon")
    extract_result = extract_mp3stego(sample, output, password="Canon")

    assert inspect_result.operation == "audio.mp3stego.inspect"
    assert inspect_result.embedded_bytes == len(encrypted)
    assert inspect_result.selected_bits >= (4 + len(encrypted)) * 8
    assert extract_result.password_used is True
    assert output.read_bytes() == b"flag{mp3stego-pass}"


def test_mp3stego_decode_payload_rejects_wrong_password(tmp_path: Path) -> None:
    sample = tmp_path / "sample.mp3"
    encrypted = _mp3stego_sample(sample, b"secret", password="right")

    try:
        decode_mp3stego_payload(encrypted, password="wrong")
    except ValueError as error:
        assert "payload" in str(error) or "invalid" in str(error)
    else:  # pragma: no cover
        raise AssertionError("wrong password unexpectedly decoded")


def test_mp3stego_source_state_machine_roundtrip() -> None:
    source = _StegoOpenEmbeddedText(b"\x01\x02\x03\x04", password="pass", length_size=4)
    sink = _StegoCreateEmbeddedText(password="pass", length_size=4, max_payload_bytes=16)

    while not source.finished:
        hidden_bit = source.get_next_bit()
        sink.save_hidden_bit(0 if hidden_bit == DO_NOTHING else hidden_bit)

    packet = sink.flush()
    assert packet.raw == b"\x01\x02\x03\x04"
    assert packet.embedded_bytes == 4
    assert packet.selected_bits == 64


def test_mp3stego_cli_extract_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    sample = tmp_path / "sample.mp3"
    output = tmp_path / "hidden.txt"
    _mp3stego_sample(sample, b"flag{cli-mp3stego}", password="")

    assert (
        main(["audio", "mp3stego", "extract", str(sample), "-p", "", "-o", str(output), "--json"])
        == 0
    )

    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "audio.mp3stego.extract"
    assert data["output_path"] == str(output)
    assert output.read_bytes() == b"flag{cli-mp3stego}"


def test_mp3stego_cli_brute_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    sample = tmp_path / "sample.mp3"
    output = tmp_path / "hidden.txt"
    wordlist = tmp_path / "words.txt"
    _mp3stego_sample(sample, b"flag{brute-mp3stego}", password="Canon")
    wordlist.write_text("alpha\nCanon\nomega\n", encoding="utf-8")

    assert (
        main(
            [
                "audio",
                "mp3stego",
                "brute",
                str(sample),
                "--wordlist",
                str(wordlist),
                "--contains",
                "flag{",
                "--no-empty",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )

    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "audio.mp3stego.brute"
    assert data["found_password"] == "Canon"
    assert output.read_bytes() == b"flag{brute-mp3stego}"


def test_mp3stego_native_encode_mp3_roundtrip(tmp_path: Path) -> None:
    carrier = tmp_path / "carrier.mp3"
    payload = tmp_path / "data.txt"
    stego = tmp_path / "stego.mp3"
    output = tmp_path / "out.txt"
    carrier.write_bytes(b"".join(_mp3_frame([0, 0]) for _ in range(600)))
    payload.write_text("secret", encoding="utf-8")

    result = encode_mp3stego(carrier, stego, payload_path=payload, password="Canon")
    extract_mp3stego(stego, output, password="Canon")

    assert result.operation == "audio.mp3stego.encode-native"
    assert result.executable == "python"
    assert result.frames == 600
    assert result.payload_bytes == len(b"secret")
    assert output.read_bytes() == b"secret"


def test_mp3stego_cli_encode_native_ignores_legacy_encoder_option(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    carrier = tmp_path / "carrier.mp3"
    payload = tmp_path / "data.txt"
    stego = tmp_path / "stego.mp3"
    output = tmp_path / "out.txt"
    carrier.write_bytes(b"".join(_mp3_frame([0, 0]) for _ in range(600)))
    payload.write_text("secret", encoding="utf-8")

    assert (
        main(
            [
                "audio",
                "mp3stego",
                "encode",
                str(carrier),
                "--payload",
                str(payload),
                "-o",
                str(stego),
                "--json",
            ]
        )
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "audio.mp3stego.encode-native"
    assert data["executable"] == "python"
    extract_mp3stego(stego, output, password="")
    assert output.read_bytes() == b"secret"


def test_mp3stego_native_encode_wav_builds_synthetic_carrier(tmp_path: Path) -> None:
    wav = tmp_path / "sound.wav"
    payload = tmp_path / "data.txt"
    stego = tmp_path / "sound.mp3"
    output = tmp_path / "out.txt"
    wav.write_bytes(b"RIFF\x04\x00\x00\x00WAVE")
    payload.write_text("wav-secret", encoding="utf-8")

    result = encode_mp3stego(wav, stego, payload_path=payload, password="")
    extract_mp3stego(stego, output, password="")

    assert result.operation == "audio.mp3stego.encode-native"
    assert result.mode == "encode-native-synthetic"
    assert output.read_bytes() == b"wav-secret"
