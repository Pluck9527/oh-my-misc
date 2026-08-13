from __future__ import annotations

import gzip
import json
import stat
import sys
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.mp3stego import (
    _encrypt_mp3stego_bytes,
    _MP3StegoPRNG,
    decode_mp3stego_payload,
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


def test_mp3stego_encode_invokes_external_tool(tmp_path: Path) -> None:
    encoder = tmp_path / "Encode.exe"
    script = f"""#!{sys.executable}
from pathlib import Path
import sys
out = Path(sys.argv[-1])
out.write_bytes(b'MP3')
print('encoded ' + str(out))
"""
    encoder.write_text(script, encoding="utf-8")
    encoder.chmod(encoder.stat().st_mode | stat.S_IXUSR)
    wav = tmp_path / "sound.wav"
    payload = tmp_path / "data.txt"
    output = tmp_path / "sound.mp3"
    wav.write_bytes(b"RIFFdemoWAVE")
    payload.write_text("secret", encoding="utf-8")

    assert (
        main(
            [
                "audio",
                "mp3stego",
                "encode",
                str(wav),
                "--payload",
                str(payload),
                "--encoder",
                str(encoder),
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    assert output.read_bytes() == b"MP3"
