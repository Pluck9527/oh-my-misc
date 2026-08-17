from __future__ import annotations

import json
from pathlib import Path

from oh_my_misc import lyra as lyra_module
from oh_my_misc.cli import main
from oh_my_misc.lyra import decode_lyra, encode_lyra, inspect_lyra, packet_size_for_bitrate


class _FakeNativeLyraLibrary:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.calls: list[dict[str, object]] = []

    def version(self) -> str:
        return "fake-google-lyra-capi"

    def decode_file(
        self,
        input_path: Path,
        output_path: Path,
        *,
        sample_rate: int,
        bitrate: int,
        randomize_num_samples: bool,
        packet_loss_rate: float,
        average_burst_length: float,
        fixed_starts: list[float],
        fixed_durations: list[float],
        model_path: Path,
    ) -> None:
        self.calls.append(
            {
                "mode": "decode",
                "input_path": input_path,
                "output_path": output_path,
                "sample_rate": sample_rate,
                "bitrate": bitrate,
                "randomize_num_samples": randomize_num_samples,
                "packet_loss_rate": packet_loss_rate,
                "average_burst_length": average_burst_length,
                "fixed_starts": fixed_starts,
                "fixed_durations": fixed_durations,
                "model_path": model_path,
            }
        )
        output_path.write_bytes(b"RIFF" + b"lyra-decoded" + str(bitrate).encode())

    def encode_file(
        self,
        input_path: Path,
        output_path: Path,
        *,
        bitrate: int,
        enable_preprocessing: bool,
        enable_dtx: bool,
        model_path: Path,
    ) -> None:
        self.calls.append(
            {
                "mode": "encode",
                "input_path": input_path,
                "output_path": output_path,
                "bitrate": bitrate,
                "enable_preprocessing": enable_preprocessing,
                "enable_dtx": enable_dtx,
                "model_path": model_path,
            }
        )
        output_path.write_bytes(b"L" * 16)


def _patch_fake_library(monkeypatch, tmp_path: Path) -> _FakeNativeLyraLibrary:  # type: ignore[no-untyped-def]
    fake = _FakeNativeLyraLibrary(tmp_path / "libomm_lyra_native.so")
    monkeypatch.setattr(lyra_module, "_load_native_library", lambda explicit=None: fake)
    return fake


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
    assert result.backend == "native-wrapper"
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
    assert data["backend"] == "native-wrapper"


def test_lyra_decode_uses_native_wrapper(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    fake = _patch_fake_library(monkeypatch, tmp_path)
    encoded = tmp_path / "message.lyra"
    encoded.write_bytes(b"B" * 16)
    output = tmp_path / "message.wav"

    result = decode_lyra(
        encoded,
        output,
        native_library=fake.path,
        bitrate=3200,
        sample_rate=16000,
        packet_loss_rate=0.25,
        fixed_packet_loss_pattern="0,0.02,1.5,0.04",
    )

    assert result.operation == "audio.lyra.decode"
    assert result.packet_size == 8
    assert result.packet_count == 2
    assert result.returncode == 0
    assert result.executable == str(fake.path)
    assert result.library_path == str(fake.path)
    assert result.command[:2] == ["native-lyra", "decode"]
    assert output.read_bytes() == b"RIFFlyra-decoded3200"
    assert fake.calls[0]["fixed_starts"] == [0.0, 1.5]
    assert fake.calls[0]["fixed_durations"] == [0.02, 0.04]


def test_lyra_encode_uses_native_wrapper(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    fake = _patch_fake_library(monkeypatch, tmp_path)
    wav = tmp_path / "speech.wav"
    wav.write_bytes(b"RIFFdemoWAVE")
    output = tmp_path / "speech.lyra"

    result = encode_lyra(wav, output, native_library=fake.path, bitrate=3200)

    assert result.operation == "audio.lyra.encode"
    assert result.written_bytes == 16
    assert result.packet_count == 2
    assert result.backend == "native-wrapper"
    assert result.command[:2] == ["native-lyra", "encode"]
    assert output.read_bytes() == b"L" * 16
    assert fake.calls[0]["mode"] == "encode"


def test_lyra_cli_decode_json_uses_native_wrapper(
    monkeypatch, tmp_path: Path, capsys
) -> None:  # type: ignore[no-untyped-def]
    fake = _patch_fake_library(monkeypatch, tmp_path)
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
                "--library",
                str(fake.path),
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
    assert data["backend"] == "native-wrapper"
    assert data["library_path"] == str(fake.path)
    assert data["output_path"] == str(output)
    assert output.exists()


def test_lyra_cli_encode_json_uses_native_wrapper(
    monkeypatch, tmp_path: Path, capsys
) -> None:  # type: ignore[no-untyped-def]
    fake = _patch_fake_library(monkeypatch, tmp_path)
    wav = tmp_path / "clip.wav"
    wav.write_bytes(b"RIFFdemoWAVE")
    output = tmp_path / "clip.lyra"

    assert (
        main(
            [
                "audio",
                "lyra",
                "encode",
                str(wav),
                "--library",
                str(fake.path),
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
    assert data["operation"] == "audio.lyra.encode"
    assert data["backend"] == "native-wrapper"
    assert data["library_path"] == str(fake.path)
    assert data["output_path"] == str(output)
    assert output.read_bytes() == b"L" * 16
