from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

from oh_my_misc.cli import main
from oh_my_misc.lyra import decode_lyra, encode_lyra, inspect_lyra, packet_size_for_bitrate


def _fake_decoder(path: Path) -> None:
    script = f"""#!{sys.executable}
from __future__ import annotations
from pathlib import Path
import sys
args = {{}}
for item in sys.argv[1:]:
    if item.startswith('--') and '=' in item:
        key, value = item[2:].split('=', 1)
        args[key] = value
encoded = Path(args['encoded_path'])
out_dir = Path(args['output_dir'])
suffix = args.get('output_suffix', '_decoded')
out_dir.mkdir(parents=True, exist_ok=True)
out = out_dir / (encoded.stem + suffix + '.wav')
out.write_bytes(b'RIFF' + b'lyra-decoded' + args.get('bitrate', '').encode())
print('decoded ' + str(out))
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _fake_encoder(path: Path) -> None:
    script = f"""#!{sys.executable}
from __future__ import annotations
from pathlib import Path
import sys
args = {{}}
for item in sys.argv[1:]:
    if item.startswith('--') and '=' in item:
        key, value = item[2:].split('=', 1)
        args[key] = value
source = Path(args['input_path'])
out_dir = Path(args['output_dir'])
out_dir.mkdir(parents=True, exist_ok=True)
out = out_dir / (source.stem + '.lyra')
out.write_bytes(b'L' * 16)
print('encoded ' + str(out))
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_lyra_packet_size_matches_google_cli_bitrates() -> None:
    assert packet_size_for_bitrate(3200) == 8
    assert packet_size_for_bitrate(6000) == 15
    assert packet_size_for_bitrate(9200) == 23


def test_lyra_inspect_lists_packet_candidates(tmp_path: Path) -> None:
    sample = tmp_path / "voice.lyra"
    sample.write_bytes(b"A" * 24)

    result = inspect_lyra(sample, bitrate=3200)

    assert result.operation == "audio.lyra.inspect"
    assert result.bitrate == 3200
    assert result.packet_size == 8
    assert result.packet_count == 3
    assert result.trailing_bytes == 0
    assert result.duration_seconds == 0.06
    exact = [candidate["bitrate"] for candidate in result.candidates if candidate["exact"]]
    assert exact == [3200]


def test_lyra_cli_inspect_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    sample = tmp_path / "voice.lyra"
    sample.write_bytes(b"A" * 45)

    assert main(["audio", "lyra", "inspect", str(sample), "--bitrate", "6000", "--json"]) == 0

    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "audio.lyra.inspect"
    assert data["bitrate"] == 6000
    assert data["packet_size"] == 15
    assert data["packet_count"] == 3


def test_lyra_decode_invokes_external_decoder(tmp_path: Path) -> None:
    decoder = tmp_path / "decoder_main"
    _fake_decoder(decoder)
    encoded = tmp_path / "message.lyra"
    encoded.write_bytes(b"B" * 16)
    output = tmp_path / "message.wav"

    result = decode_lyra(encoded, output, decoder=decoder, bitrate=3200, sample_rate=16000)

    assert result.operation == "audio.lyra.decode"
    assert result.packet_size == 8
    assert result.packet_count == 2
    assert result.returncode == 0
    assert output.read_bytes() == b"RIFFlyra-decoded3200"
    assert any(part == "--output_suffix=" for part in result.command)


def test_lyra_encode_invokes_external_encoder(tmp_path: Path) -> None:
    encoder = tmp_path / "encoder_main"
    _fake_encoder(encoder)
    wav = tmp_path / "speech.wav"
    wav.write_bytes(b"RIFFdemoWAVE")
    output = tmp_path / "speech.lyra"

    result = encode_lyra(wav, output, encoder=encoder, bitrate=3200)

    assert result.operation == "audio.lyra.encode"
    assert result.written_bytes == 16
    assert result.packet_count == 2
    assert output.read_bytes() == b"L" * 16


def test_lyra_cli_decode_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    decoder = tmp_path / "decoder_main"
    _fake_decoder(decoder)
    encoded = tmp_path / "clip.lyra"
    encoded.write_bytes(b"C" * 16)
    output = tmp_path / "clip.wav"

    assert (
        main(
            [
                "audio",
                "lyra",
                "decode",
                str(encoded),
                "--decoder",
                str(decoder),
                "--bitrate",
                "3200",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )

    data = json.loads(capsys.readouterr().out)
    assert data["operation"] == "audio.lyra.decode"
    assert data["output_path"] == str(output)
    assert output.exists()
