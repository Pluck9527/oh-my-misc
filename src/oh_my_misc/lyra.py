from __future__ import annotations

import math
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

FRAME_RATE = 50
NUM_CHANNELS = 1
SUPPORTED_BITRATES = (3200, 6000, 9200)
SUPPORTED_SAMPLE_RATES = (8000, 16000, 32000, 48000)


@dataclass(frozen=True)
class LyraPacketCandidate:
    bitrate: int
    packet_size: int
    packet_count: int
    trailing_bytes: int
    duration_seconds: float
    exact: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LyraResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    bitrate: int | None
    sample_rate: int | None
    packet_size: int | None
    packet_count: int | None
    trailing_bytes: int
    duration_seconds: float | None
    executable: str
    model_path: str
    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    written_bytes: int
    candidates: list[dict[str, Any]]
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


def packet_size_for_bitrate(bitrate: int) -> int:
    _validate_bitrate(bitrate)
    return math.ceil(bitrate / (FRAME_RATE * 8))


def inspect_lyra(input_path: Path, *, bitrate: int | None = None) -> LyraResult:
    input_path = Path(input_path)
    size = input_path.stat().st_size
    candidates = [_candidate_for_size(size, candidate) for candidate in SUPPORTED_BITRATES]
    selected: LyraPacketCandidate | None = None
    if bitrate is not None:
        _validate_bitrate(bitrate)
        selected = _candidate_for_size(size, bitrate)
    exact_candidates = [candidate for candidate in candidates if candidate.exact]
    if selected is None and len(exact_candidates) == 1:
        selected = exact_candidates[0]

    return LyraResult(
        operation="audio.lyra.inspect",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        mode="inspect",
        bitrate=selected.bitrate if selected is not None else bitrate,
        sample_rate=None,
        packet_size=selected.packet_size if selected is not None else None,
        packet_count=selected.packet_count if selected is not None else None,
        trailing_bytes=selected.trailing_bytes if selected is not None else 0,
        duration_seconds=selected.duration_seconds if selected is not None else None,
        executable="",
        model_path="",
        command=[],
        stdout="",
        stderr="",
        returncode=0,
        written_bytes=0,
        candidates=[candidate.to_dict() for candidate in candidates],
        count=len(candidates),
    )


def decode_lyra(
    input_path: Path,
    output_path: Path,
    *,
    bitrate: int = 3200,
    sample_rate: int = 16000,
    decoder: Path | None = None,
    model_path: Path | None = None,
    randomize_num_samples: bool = False,
    packet_loss_rate: float = 0.0,
    average_burst_length: float = 1.0,
    fixed_packet_loss_pattern: str = "",
) -> LyraResult:
    _validate_bitrate(bitrate)
    _validate_sample_rate(sample_rate)
    input_path = Path(input_path)
    output_path = Path(output_path)
    executable = _resolve_binary("decoder", decoder)
    packet_size = packet_size_for_bitrate(bitrate)
    size = input_path.stat().st_size
    packet_count = size // packet_size
    trailing_bytes = size % packet_size
    with tempfile.TemporaryDirectory(prefix="omm-lyra-decode-") as temp_dir:
        temp_path = Path(temp_dir)
        command = [
            str(executable),
            f"--encoded_path={input_path}",
            f"--output_dir={temp_path}",
            "--output_suffix=",
            f"--sample_rate_hz={sample_rate}",
            f"--bitrate={bitrate}",
        ]
        if model_path is not None:
            command.append(f"--model_path={model_path}")
        if randomize_num_samples:
            command.append("--randomize_num_samples_requested=true")
        if packet_loss_rate:
            command.append(f"--packet_loss_rate={packet_loss_rate}")
        if average_burst_length != 1.0:
            command.append(f"--average_burst_length={average_burst_length}")
        if fixed_packet_loss_pattern:
            command.append(f"--fixed_packet_loss_pattern={fixed_packet_loss_pattern}")
        completed = _run_command(command)
        generated = temp_path / f"{input_path.stem}.wav"
        if not generated.exists():
            wavs = sorted(temp_path.glob("*.wav"))
            if not wavs:
                raise ValueError("Lyra decoder finished without producing a WAV file")
            generated = wavs[0]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(generated), output_path)
    written_bytes = output_path.stat().st_size
    return LyraResult(
        operation="audio.lyra.decode",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="decode",
        bitrate=bitrate,
        sample_rate=sample_rate,
        packet_size=packet_size,
        packet_count=packet_count,
        trailing_bytes=trailing_bytes,
        duration_seconds=packet_count / FRAME_RATE,
        executable=str(executable),
        model_path=str(model_path) if model_path is not None else "",
        command=command,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        written_bytes=written_bytes,
        candidates=[],
    )


def encode_lyra(
    input_path: Path,
    output_path: Path,
    *,
    bitrate: int = 3200,
    encoder: Path | None = None,
    model_path: Path | None = None,
    enable_preprocessing: bool = False,
    enable_dtx: bool = False,
) -> LyraResult:
    _validate_bitrate(bitrate)
    input_path = Path(input_path)
    output_path = Path(output_path)
    executable = _resolve_binary("encoder", encoder)
    with tempfile.TemporaryDirectory(prefix="omm-lyra-encode-") as temp_dir:
        temp_path = Path(temp_dir)
        command = [
            str(executable),
            f"--input_path={input_path}",
            f"--output_dir={temp_path}",
            f"--bitrate={bitrate}",
        ]
        if model_path is not None:
            command.append(f"--model_path={model_path}")
        if enable_preprocessing:
            command.append("--enable_preprocessing=true")
        if enable_dtx:
            command.append("--enable_dtx=true")
        completed = _run_command(command)
        generated = temp_path / f"{input_path.stem}.lyra"
        if not generated.exists():
            lyras = sorted(temp_path.glob("*.lyra"))
            if not lyras:
                raise ValueError("Lyra encoder finished without producing a .lyra file")
            generated = lyras[0]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(generated), output_path)
    written_bytes = output_path.stat().st_size
    packet_size = packet_size_for_bitrate(bitrate)
    packet_count = written_bytes // packet_size
    trailing_bytes = written_bytes % packet_size
    return LyraResult(
        operation="audio.lyra.encode",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="encode",
        bitrate=bitrate,
        sample_rate=None,
        packet_size=packet_size,
        packet_count=packet_count,
        trailing_bytes=trailing_bytes,
        duration_seconds=packet_count / FRAME_RATE,
        executable=str(executable),
        model_path=str(model_path) if model_path is not None else "",
        command=command,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        written_bytes=written_bytes,
        candidates=[],
    )


def _candidate_for_size(size: int, bitrate: int) -> LyraPacketCandidate:
    packet_size = packet_size_for_bitrate(bitrate)
    packet_count = size // packet_size
    trailing_bytes = size % packet_size
    return LyraPacketCandidate(
        bitrate=bitrate,
        packet_size=packet_size,
        packet_count=packet_count,
        trailing_bytes=trailing_bytes,
        duration_seconds=packet_count / FRAME_RATE,
        exact=trailing_bytes == 0 and packet_count > 0,
    )


def _validate_bitrate(bitrate: int) -> None:
    if bitrate not in SUPPORTED_BITRATES:
        supported = ", ".join(str(value) for value in SUPPORTED_BITRATES)
        raise ValueError(f"unsupported Lyra bitrate {bitrate}; expected one of: {supported}")


def _validate_sample_rate(sample_rate: int) -> None:
    if sample_rate not in SUPPORTED_SAMPLE_RATES:
        supported = ", ".join(str(value) for value in SUPPORTED_SAMPLE_RATES)
        raise ValueError(
            f"unsupported Lyra sample rate {sample_rate}; expected one of: {supported}"
        )


def _resolve_binary(kind: str, explicit: Path | None) -> Path:
    if explicit is not None:
        return _check_executable(Path(explicit))
    env_name = "LYRA_DECODER" if kind == "decoder" else "LYRA_ENCODER"
    env_value = os.environ.get(env_name)
    if env_value:
        return _check_executable(Path(env_value))
    names = (
        ("decoder_main", "lyra-decoder", "lyra_decoder")
        if kind == "decoder"
        else ("encoder_main", "lyra-encoder", "lyra_encoder")
    )
    for name in names:
        found = shutil.which(name)
        if found:
            return _check_executable(Path(found))
    suffix = "decoder_main" if kind == "decoder" else "encoder_main"
    for root in (Path.cwd(), Path.cwd() / "third_party" / "lyra"):
        candidate = root / "bazel-bin" / "lyra" / "cli_example" / suffix
        if candidate.exists():
            return _check_executable(candidate)
    build_target = (
        "lyra/cli_example:decoder_main" if kind == "decoder" else "lyra/cli_example:encoder_main"
    )
    raise ValueError(
        f"Lyra {kind} executable not found; build google/lyra with `bazel build -c opt {build_target}` "
        f"or pass --{kind} /path/to/{suffix}"
    )


def _check_executable(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(path)
    if not os.access(path, os.X_OK):
        raise PermissionError(f"executable bit is not set: {path}")
    return path


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        detail = stderr or stdout or f"exit status {completed.returncode}"
        raise ValueError(f"Lyra command failed: {detail}")
    return completed
