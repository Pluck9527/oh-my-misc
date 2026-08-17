from __future__ import annotations

import ctypes
import math
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

FRAME_RATE = 50
NUM_CHANNELS = 1
SUPPORTED_BITRATES = (3200, 6000, 9200)
SUPPORTED_SAMPLE_RATES = (8000, 16000, 32000, 48000)
_VENDOR_ROOT = Path(__file__).resolve().parent / "_vendor" / "google_lyra"
_DEFAULT_MODEL_PATH = _VENDOR_ROOT / "lyra" / "model_coeffs"
_ERROR_BUFFER_SIZE = 4096


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
    backend: str = "native-wrapper"
    library_path: str = ""
    source_path: str = str(_VENDOR_ROOT)

    def to_dict(self) -> dict[str, Any]:
        return {"status": "success", **asdict(self)}


class _NativeLyraLibrary:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._dll = ctypes.CDLL(str(self.path))
        self._configure_symbols()

    def _configure_symbols(self) -> None:
        self._dll.omm_lyra_encode_file.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self._dll.omm_lyra_encode_file.restype = ctypes.c_int
        self._dll.omm_lyra_decode_file.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_float,
            ctypes.c_float,
            ctypes.POINTER(ctypes.c_float),
            ctypes.POINTER(ctypes.c_float),
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self._dll.omm_lyra_decode_file.restype = ctypes.c_int
        self._dll.omm_lyra_version.argtypes = []
        self._dll.omm_lyra_version.restype = ctypes.c_char_p

    def version(self) -> str:
        raw = self._dll.omm_lyra_version()
        return raw.decode("utf-8", errors="replace") if raw else "google-lyra-capi"

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
        error = ctypes.create_string_buffer(_ERROR_BUFFER_SIZE)
        status = self._dll.omm_lyra_encode_file(
            _path_bytes(input_path),
            _path_bytes(output_path),
            int(bitrate),
            int(enable_preprocessing),
            int(enable_dtx),
            _path_bytes(model_path),
            error,
            ctypes.sizeof(error),
        )
        _raise_on_native_error("encode", status, error)

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
        error = ctypes.create_string_buffer(_ERROR_BUFFER_SIZE)
        starts_arg: ctypes.Array[ctypes.c_float] | None = None
        durations_arg: ctypes.Array[ctypes.c_float] | None = None
        if fixed_starts:
            starts_arg = (ctypes.c_float * len(fixed_starts))(*fixed_starts)
            durations_arg = (ctypes.c_float * len(fixed_durations))(*fixed_durations)
        status = self._dll.omm_lyra_decode_file(
            _path_bytes(input_path),
            _path_bytes(output_path),
            int(sample_rate),
            int(bitrate),
            int(randomize_num_samples),
            ctypes.c_float(packet_loss_rate),
            ctypes.c_float(average_burst_length),
            starts_arg,
            durations_arg,
            len(fixed_starts),
            _path_bytes(model_path),
            error,
            ctypes.sizeof(error),
        )
        _raise_on_native_error("decode", status, error)


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
        command=["native-lyra", "inspect", str(input_path)],
        stdout="",
        stderr="",
        returncode=0,
        written_bytes=0,
        candidates=[candidate.to_dict() for candidate in candidates],
        count=len(candidates),
        library_path="",
    )


def decode_lyra(
    input_path: Path,
    output_path: Path,
    *,
    bitrate: int = 3200,
    sample_rate: int = 16000,
    decoder: Path | None = None,
    native_library: Path | None = None,
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
    output_path.parent.mkdir(parents=True, exist_ok=True)
    packet_size = packet_size_for_bitrate(bitrate)
    size = input_path.stat().st_size
    packet_count = size // packet_size
    trailing_bytes = size % packet_size
    starts, durations = _parse_packet_loss_pattern(fixed_packet_loss_pattern)
    library = _load_native_library(native_library or decoder)
    resolved_model_path = _resolve_model_path(model_path)
    library.decode_file(
        input_path,
        output_path,
        sample_rate=sample_rate,
        bitrate=bitrate,
        randomize_num_samples=randomize_num_samples,
        packet_loss_rate=packet_loss_rate,
        average_burst_length=average_burst_length,
        fixed_starts=starts,
        fixed_durations=durations,
        model_path=resolved_model_path,
    )
    if not output_path.exists():
        raise ValueError("Lyra native wrapper finished without producing a WAV file")
    written_bytes = output_path.stat().st_size
    command = [
        "native-lyra",
        "decode",
        str(input_path),
        "-o",
        str(output_path),
        "--library",
        str(library.path),
        "--model-path",
        str(resolved_model_path),
        "--sample-rate",
        str(sample_rate),
        "--bitrate",
        str(bitrate),
    ]
    if randomize_num_samples:
        command.append("--randomize-num-samples")
    if packet_loss_rate:
        command.extend(["--packet-loss-rate", str(packet_loss_rate)])
    if average_burst_length != 1.0:
        command.extend(["--average-burst-length", str(average_burst_length)])
    if fixed_packet_loss_pattern:
        command.extend(["--fixed-packet-loss-pattern", fixed_packet_loss_pattern])
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
        executable=str(library.path),
        model_path=str(resolved_model_path),
        command=command,
        stdout=library.version(),
        stderr="",
        returncode=0,
        written_bytes=written_bytes,
        candidates=[],
        library_path=str(library.path),
    )


def encode_lyra(
    input_path: Path,
    output_path: Path,
    *,
    bitrate: int = 3200,
    encoder: Path | None = None,
    native_library: Path | None = None,
    model_path: Path | None = None,
    enable_preprocessing: bool = False,
    enable_dtx: bool = False,
) -> LyraResult:
    _validate_bitrate(bitrate)
    input_path = Path(input_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    library = _load_native_library(native_library or encoder)
    resolved_model_path = _resolve_model_path(model_path)
    library.encode_file(
        input_path,
        output_path,
        bitrate=bitrate,
        enable_preprocessing=enable_preprocessing,
        enable_dtx=enable_dtx,
        model_path=resolved_model_path,
    )
    if not output_path.exists():
        raise ValueError("Lyra native wrapper finished without producing a .lyra file")
    written_bytes = output_path.stat().st_size
    packet_size = packet_size_for_bitrate(bitrate)
    packet_count = written_bytes // packet_size
    trailing_bytes = written_bytes % packet_size
    command = [
        "native-lyra",
        "encode",
        str(input_path),
        "-o",
        str(output_path),
        "--library",
        str(library.path),
        "--model-path",
        str(resolved_model_path),
        "--bitrate",
        str(bitrate),
    ]
    if enable_preprocessing:
        command.append("--enable-preprocessing")
    if enable_dtx:
        command.append("--enable-dtx")
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
        executable=str(library.path),
        model_path=str(resolved_model_path),
        command=command,
        stdout=library.version(),
        stderr="",
        returncode=0,
        written_bytes=written_bytes,
        candidates=[],
        library_path=str(library.path),
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


def _parse_packet_loss_pattern(text: str) -> tuple[list[float], list[float]]:
    if not text:
        return [], []
    values = [float(part.strip()) for part in text.split(",") if part.strip()]
    if len(values) % 2:
        raise ValueError("fixed packet loss pattern must contain start,duration pairs")
    if any(value < 0 for value in values):
        raise ValueError("fixed packet loss pattern values must be non-negative")
    return values[0::2], values[1::2]


def _resolve_model_path(explicit: Path | None) -> Path:
    candidate = explicit or (
        Path(value) if (value := os.environ.get("OMM_LYRA_MODEL_PATH")) else None
    )
    path = Path(candidate) if candidate is not None else _DEFAULT_MODEL_PATH
    if not path.exists():
        raise FileNotFoundError(f"Lyra model path does not exist: {path}")
    return path


def _load_native_library(explicit: Path | None = None) -> _NativeLyraLibrary:
    return _NativeLyraLibrary(_resolve_library_path(explicit))


def _resolve_library_path(explicit: Path | None = None) -> Path:
    if explicit is not None:
        path = Path(explicit)
        if not path.exists():
            raise FileNotFoundError(path)
        return path
    env_value = os.environ.get("OMM_LYRA_LIBRARY")
    if env_value:
        path = Path(env_value)
        if not path.exists():
            raise FileNotFoundError(path)
        return path
    for candidate in _candidate_library_paths():
        if candidate.exists():
            return candidate
    searched = "\n".join(f"  - {path}" for path in _candidate_library_paths())
    build_hint = f"cd {_VENDOR_ROOT} && bazel build -c opt //omm_native:libomm_lyra_native.so"
    raise ValueError(
        "Lyra native wrapper library not found. Build the bundled Google Lyra source with: "
        f"{build_hint}\nsearched:\n{searched}"
    )


def _candidate_library_paths() -> list[Path]:
    names = _library_filenames()
    roots = [
        _VENDOR_ROOT / "bazel-bin" / "omm_native",
        _VENDOR_ROOT / "omm_native",
        _VENDOR_ROOT,
        Path.cwd() / "src" / "oh_my_misc" / "_vendor" / "google_lyra" / "bazel-bin" / "omm_native",
        Path.cwd() / "third_party" / "google_lyra" / "bazel-bin" / "omm_native",
    ]
    return [root / name for root in roots for name in names]


def _library_filenames() -> tuple[str, ...]:
    if sys.platform == "win32":
        return ("omm_lyra_native.dll", "libomm_lyra_native.dll")
    if sys.platform == "darwin":
        return ("libomm_lyra_native.dylib", "libomm_lyra_native.so")
    return ("libomm_lyra_native.so",)


def _path_bytes(path: Path) -> bytes:
    return os.fsencode(Path(path))


def _raise_on_native_error(operation: str, status: int, error: ctypes.Array[ctypes.c_char]) -> None:
    if status == 0:
        return
    detail = bytes(error.value).decode("utf-8", errors="replace") or f"status {status}"
    raise ValueError(f"Lyra native {operation} failed: {detail}")
