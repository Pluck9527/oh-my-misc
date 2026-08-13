from __future__ import annotations

import math
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

JPEG_TYPES = {
    "j": "jsteg",
    "o": "outguess",
    "p": "jphide",
    "i": "invisible-secrets",
    "f": "f5",
    "F": "f5-slow",
    "a": "appended",
}

SIGNATURES = {
    "jsteg": (b"jsteg", b"jsteg-shell", b"jsteg-jpeg"),
    "outguess": (b"outguess", b"outguess 0.", b"outguess-data"),
    "jphide": (b"jphide", b"jpseek", b"jphs", b"jphide&seek", b"jphide and seek"),
    "invisible-secrets": (b"invisible secrets", b"invisiblesecrets", b"invisible-secret"),
    "f5": (b"f5-steganography", b"f5 steganography", b"f5embed", b"f5extract"),
    "f5-slow": (b"f5-steganography", b"f5 steganography", b"f5embed", b"f5extract"),
    "appended": (),
}

F5_ENCODER_COMMENT = b"JPEG Encoder Copyright 1998, James R. Weeks and BioElectroMech."


@dataclass(frozen=True)
class StegdetectFinding:
    input_path: str
    kind: str
    score: float
    stars: str
    positive: bool
    evidence: list[str]


@dataclass(frozen=True)
class StegdetectResult:
    operation: str
    input_paths: list[str]
    output_path: str | None
    output_paths: list[str]
    types: str
    sensitivity: float
    findings: list[dict[str, object]]
    count: int
    positive_count: int

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def run_stegdetect(
    input_paths: list[Path],
    *,
    types: str = "jopifa",
    sensitivity: float = 10.0,
    output_path: Path | None = None,
) -> StegdetectResult:
    """Run a stegdetect-style JPEG triage for common legacy stego tools."""

    if not input_paths:
        raise ValueError("至少需要一个 JPEG 输入文件")
    if sensitivity <= 0:
        raise ValueError("sensitivity 必须大于 0")
    selected = _parse_types(types)
    findings: list[StegdetectFinding] = []
    for path in input_paths:
        findings.extend(_detect_one(path, selected, sensitivity))
    positive_count = sum(1 for finding in findings if finding.positive)
    lines = [_format_line(finding) for finding in findings]
    outputs: list[str] = []
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        outputs.append(str(output_path))
    return StegdetectResult(
        operation="image.stegdetect",
        input_paths=[str(path) for path in input_paths],
        output_path=str(output_path) if output_path is not None else None,
        output_paths=outputs,
        types=types,
        sensitivity=sensitivity,
        findings=[asdict(finding) for finding in findings],
        count=len(findings),
        positive_count=positive_count,
    )


def _detect_one(path: Path, selected: list[str], sensitivity: float) -> list[StegdetectFinding]:
    if not path.is_file():
        raise FileNotFoundError(f"文件不存在：{path}")
    data = path.read_bytes()
    if not data.startswith(b"\xff\xd8"):
        raise ValueError(f"不是 JPEG 文件：{path}")
    segments, entropy = _parse_jpeg(data)
    findings: list[StegdetectFinding] = []
    for kind in selected:
        score, evidence = _score_kind(kind, data, segments, entropy)
        positive = score >= sensitivity
        findings.append(
            StegdetectFinding(
                input_path=str(path),
                kind=kind,
                score=round(score, 3),
                stars=_stars(score, sensitivity),
                positive=positive,
                evidence=evidence,
            )
        )
    return findings


def _parse_types(types: str) -> list[str]:
    selected: list[str] = []
    for code in types:
        if code in {"-", ",", " ", "\t"}:
            continue
        key = code if code == "F" else code.lower()
        if key not in JPEG_TYPES:
            raise ValueError(f"不支持的 stegdetect 类型：{code}")
        kind = JPEG_TYPES[key]
        if kind not in selected:
            selected.append(kind)
    if not selected:
        raise ValueError("types 至少要包含 j/o/p/i/f/F/a 中的一个")
    return selected


def _score_kind(
    kind: str,
    data: bytes,
    segments: list[tuple[int, bytes]],
    entropy: bytes,
) -> tuple[float, list[str]]:
    lowered = data.lower()
    evidence: list[str] = []
    score = 0.0
    metadata = b"\n".join(body.lower() for marker, body in segments if marker in {0xFE, *range(0xE0, 0xF0)})
    for signature in SIGNATURES[kind]:
        if signature in metadata:
            score += 30.0
            evidence.append(f"metadata signature {signature.decode('latin1', 'replace')!r}")
        elif signature in lowered:
            score += 15.0
            evidence.append(f"file signature {signature.decode('latin1', 'replace')!r}")
    if kind == "outguess":
        score += _comment_entropy_score(segments, evidence)
    if kind == "jsteg":
        score += _entropy_lsb_score(entropy, evidence)
    if kind in {"f5", "f5-slow"}:
        score += _f5_score(segments, evidence, slow=kind == "f5-slow")
    if kind == "invisible-secrets":
        score += _invisible_secrets_score(segments, evidence)
    if kind == "appended":
        score += _appended_score(data, evidence)
    return min(score, 100.0), evidence


def _f5_score(
    segments: list[tuple[int, bytes]],
    evidence: list[str],
    *,
    slow: bool,
) -> float:
    """Mirror stegdetect's cheap F5 marker and expose a slow-test placeholder.

    The original ``-tf`` first checks for the exact F5 encoder comment.  ``-tF``
    additionally runs a beta estimator over JPEG DCT coefficients; this native
    parser does not decode coefficients yet, so it reports only the compatible
    marker evidence while keeping the test selector.
    """

    comments = [body for marker, body in segments if marker == 0xFE]
    if len(comments) == 1 and comments[0] == F5_ENCODER_COMMENT:
        evidence.append("original F5 encoder comment")
        return 30.0
    if slow:
        evidence.append("F5 slow DCT beta test selected; marker-only native check")
    return 0.0


def _invisible_secrets_score(
    segments: list[tuple[int, bytes]],
    evidence: list[str],
) -> float:
    """Implement stegdetect's Invisible Secrets JPEG comment-length check."""

    comments = [body for marker, body in segments if marker == 0xFE]
    if len(comments) < 2 or len(comments[1]) < 4:
        return 0.0
    length = int.from_bytes(comments[1][:4], "little")
    remaining = length + 4
    if len(comments[1]) == remaining:
        evidence.append(f"invisible-secrets comment length={length}")
        return 30.0
    for comment in comments[1:]:
        if len(comment) > remaining:
            break
        remaining -= len(comment)
        if remaining == 0:
            evidence.append(f"invisible-secrets split comments length={length}")
            return 30.0
    return 0.0


def _appended_score(data: bytes, evidence: list[str]) -> float:
    """Detect data after JPEG EOI, like stegdetect's ``-ta`` append test."""

    trailing = _trailing_after_eoi(data)
    if not trailing:
        return 0.0
    kind = "appended"
    if len(trailing) > 22 and all(byte == 0 for byte in trailing[2:18]) and trailing[2:6] == trailing[18:22]:
        kind = "camouflage"
    elif trailing.startswith(b"\x80?\xe0P"):
        kind = "alpha-channel"
    entropy = _shannon_entropy(trailing)
    randomness = "random" if entropy >= 7.0 else "nonrandom"
    preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in trailing[:16])
    evidence.append(f"{kind} data after EOI: {len(trailing)} bytes, {randomness}, preview={preview!r}")
    return 30.0 if len(trailing) >= 4 else 10.0


def _trailing_after_eoi(data: bytes) -> bytes:
    pos = 2
    while pos < len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            return data[pos:]
        if marker == 0xDA:
            if pos + 2 > len(data):
                break
            length = struct.unpack(">H", data[pos : pos + 2])[0]
            pos = _find_entropy_end(data, pos + length)
            continue
        if marker in {0x01, *range(0xD0, 0xD8)}:
            continue
        if pos + 2 > len(data):
            break
        length = struct.unpack(">H", data[pos : pos + 2])[0]
        if length < 2:
            break
        pos += length
    return b""


def _comment_entropy_score(
    segments: list[tuple[int, bytes]],
    evidence: list[str],
) -> float:
    comments = [body for marker, body in segments if marker == 0xFE]
    if not comments:
        return 0.0
    joined = b"".join(comments)
    entropy = _shannon_entropy(joined)
    if len(joined) >= 32 and entropy > 5.5:
        evidence.append(f"high-entropy JPEG comment entropy={entropy:.2f}")
        return 5.0
    return 0.0


def _entropy_lsb_score(entropy: bytes, evidence: list[str]) -> float:
    if len(entropy) < 256:
        return 0.0
    sample = entropy[: min(len(entropy), 8192)]
    ones = sum(byte & 1 for byte in sample)
    ratio = ones / len(sample)
    if 0.49 <= ratio <= 0.51:
        evidence.append(f"entropy-data LSB balance={ratio:.3f}")
        return 3.0
    return 0.0


def _parse_jpeg(data: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    pos = 2
    segments: list[tuple[int, bytes]] = []
    entropy = bytearray()
    while pos < len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            break
        if marker == 0xDA:
            if pos + 2 > len(data):
                break
            length = struct.unpack(">H", data[pos : pos + 2])[0]
            scan_start = pos + length
            scan_end = _find_entropy_end(data, scan_start)
            entropy.extend(_unstuff_entropy(data[scan_start:scan_end]))
            pos = scan_end
            continue
        if marker in {0x01, *range(0xD0, 0xD8)}:
            continue
        if pos + 2 > len(data):
            break
        length = struct.unpack(">H", data[pos : pos + 2])[0]
        if length < 2 or pos + length > len(data):
            break
        body = data[pos + 2 : pos + length]
        segments.append((marker, body))
        pos += length
    return segments, bytes(entropy)


def _find_entropy_end(data: bytes, start: int) -> int:
    pos = start
    while pos + 1 < len(data):
        if data[pos] == 0xFF and data[pos + 1] != 0x00 and not (0xD0 <= data[pos + 1] <= 0xD7):
            return pos
        pos += 1
    return len(data)


def _unstuff_entropy(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(data):
        if pos + 1 < len(data) and data[pos] == 0xFF and data[pos + 1] == 0x00:
            out.append(0xFF)
            pos += 2
        else:
            out.append(data[pos])
            pos += 1
    return bytes(out)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _stars(score: float, sensitivity: float) -> str:
    if score >= sensitivity * 3:
        return "***"
    if score >= sensitivity * 2:
        return "**"
    if score >= sensitivity:
        return "*"
    return ""


def _format_line(finding: StegdetectFinding) -> str:
    status = f"{finding.kind}{finding.stars}" if finding.positive else "negative"
    evidence = "; ".join(finding.evidence) if finding.evidence else "no matching signature"
    return f"{finding.input_path}: {status} score={finding.score:g} evidence={evidence}"
