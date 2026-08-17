from __future__ import annotations

import re
import tempfile
import zlib
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from textwrap import fill

_NATIVE_MAGIC = b"OMMSPAM1"
_PASSWORD_MAGIC = b"OMMSPWP1"

_SPAM_GROUPS: tuple[tuple[str, str, str, str], ...] = (
    (
        "Dear Friend,",
        "Dear Professional,",
        "Dear Decision maker,",
        "Dear Internet user,",
    ),
    (
        "This letter was specially selected to be sent to you.",
        "Especially for you, this red-hot intelligence is now available.",
        "We know you are interested in receiving amazing intelligence.",
        "This message contains a limited time offer for selected people.",
    ),
    (
        "If you no longer wish to receive our publications simply reply with REMOVE.",
        "There is no need to request removal if you do not want any more mail.",
        "This is a one time mailing and you can be removed from our club immediately.",
        "You are receiving this notice because you visited one of our partner sites.",
    ),
    (
        "This mail is being sent in compliance with Senate bill 1623 Title 6 Section 304.",
        "This mail is being sent in compliance with Senate bill 2116 Title 9 Section 303.",
        "This mail is being sent in compliance with Senate bill 2416 Title 4 Section 302.",
        "This notice is being sent in compliance with all federal and state regulations.",
    ),
    (
        "This is not a get rich scheme.",
        "This is not multi level marketing.",
        "This is a legitimate business proposal.",
        "This is a risk free commercial announcement.",
    ),
    (
        "Why work for somebody else when you can become rich in just weeks.",
        "Have you ever noticed most everyone has a cell phone and people love convenience.",
        "Now is your chance to capitalize on this once in a lifetime opportunity.",
        "More people than ever are surfing the web and looking for services.",
    ),
    (
        "We will help you process your orders within seconds and sell more.",
        "We will help you increase customer response by one hundred percent.",
        "We will help you use credit cards on your website immediately.",
        "We will help you deliver information to thousands of customers.",
    ),
    (
        "You can begin at absolutely no cost to you.",
        "The best thing about our system is that it is absolutely risk free for you.",
        "You are guaranteed to succeed because we take all the risk.",
        "There is no obligation and no hidden fee of any kind.",
    ),
    (
        "But do not believe us.",
        "Do not delay another minute.",
        "Act now before this offer expires.",
        "For the sake of your family order now.",
    ),
    (
        "Prof Anderson of Wisconsin tried us and says now I am rich.",
        "Ms Simpson of Washington tried us and says my only problem is where to park my cars.",
        "Mr Jones of Nevada tried us and says everything changed overnight.",
        "Dr Ames of North Carolina tried us and says many more things are possible.",
    ),
    (
        "This offer is one hundred percent legal.",
        "This offer has been checked by our legal department.",
        "This opportunity is approved for immediate release.",
        "This publication is reserved for serious readers only.",
    ),
    (
        "Sign up a friend and you will get a discount of fifty percent.",
        "Order now and you will receive a valuable bonus absolutely free.",
        "Click today and you will be amazed by the results.",
        "Thank you for your serious consideration of our offer.",
    ),
)

_SPACE_ZERO = " "
_SPACE_ONE = "\t"


@dataclass(frozen=True)
class SpamMimicResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    backend: str
    mode: str
    payload_bytes: int = 0
    written_bytes: int = 0
    password_used: bool = False
    password_verified: bool = False
    found_password: str | None = None
    attempts: int = 0
    stdout: str = ""
    stderr: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def encode_spammimic(
    output_path: Path,
    *,
    payload_path: Path | None = None,
    text: str | None = None,
    cover_path: Path | None = None,
    password: str | None = None,
    mode: str = "spam",
    backend: str = "native",
) -> SpamMimicResult:
    payload = _load_payload(payload_path=payload_path, text=text)
    mode = _validate_mode(mode)
    _validate_backend(backend)
    output = _native_encode(payload, mode=mode, password=password, cover_path=cover_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")
    return SpamMimicResult(
        operation="text.spammimic.encode",
        input_path=str(payload_path or "<text>"),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        backend="native",
        mode=mode,
        payload_bytes=len(payload),
        written_bytes=output_path.stat().st_size,
        password_used=password is not None,
        password_verified=password is not None,
    )


def decode_spammimic(
    input_path: Path,
    output_path: Path,
    *,
    password: str | None = None,
    mode: str = "spam",
    backend: str = "auto",
) -> SpamMimicResult:
    _check_file(input_path, "SpamMimic 文本")
    mode = _validate_mode(mode)
    backend = _validate_backend(backend, allow_auto=True)
    text = input_path.read_text(encoding="utf-8", errors="replace")
    _ = backend
    payload, verified = _native_decode(text, mode=mode, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return SpamMimicResult(
        operation="text.spammimic.decode",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        backend="native",
        mode=mode,
        payload_bytes=len(payload),
        written_bytes=len(payload),
        password_used=password is not None,
        password_verified=verified,
    )


def brute_spammimic(
    input_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    mode: str = "spam",
    backend: str = "auto",
    contains: bytes | None = None,
    prefix: bytes | None = None,
    include_default: bool = True,
) -> SpamMimicResult:
    _check_file(wordlist_path, "字典文件")
    candidates: list[str] = []
    if include_default:
        candidates.append("")
    candidates.extend(
        line.rstrip("\r\n")
        for line in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    )
    seen: set[str] = set()
    attempts = 0
    with tempfile.TemporaryDirectory(prefix="omm-spammimic-") as directory:
        trial_output = Path(directory) / "trial.bin"
        for password in candidates:
            if password in seen:
                continue
            seen.add(password)
            attempts += 1
            try:
                result = decode_spammimic(
                    input_path,
                    trial_output,
                    password=password or None,
                    mode=mode,
                    backend=backend,
                )
            except (ValueError, OSError, UnicodeError):
                continue
            payload = trial_output.read_bytes()
            if contains is not None and contains not in payload:
                continue
            if prefix is not None and not payload.startswith(prefix):
                continue
            if contains is None and prefix is None and password and not result.password_verified:
                continue
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(payload)
            return SpamMimicResult(
                operation="text.spammimic.brute",
                input_path=str(input_path),
                output_path=str(output_path),
                output_paths=[str(output_path)],
                backend=result.backend,
                mode=mode,
                payload_bytes=len(payload),
                written_bytes=len(payload),
                password_used=True,
                password_verified=result.password_verified,
                found_password=password,
                attempts=attempts,
            )
    raise ValueError(f"字典未命中 SpamMimic 密码，尝试 {attempts} 个候选")


def _native_encode(
    payload: bytes, *, mode: str, password: str | None, cover_path: Path | None
) -> str:
    frame = _frame_payload(payload, password=password)
    bits = _bytes_to_bits(frame)
    if mode == "space":
        cover = cover_path.read_text(encoding="utf-8", errors="replace") if cover_path else ""
        return _encode_space_native(bits, cover)
    return _encode_spam_native(bits)


def _native_decode(text: str, *, mode: str, password: str | None) -> tuple[bytes, bool]:
    bits = _decode_space_bits(text) if mode == "space" else _decode_spam_bits(text)
    data = _bits_to_bytes(bits)
    return _unframe_payload(data, password=password)


def _frame_payload(payload: bytes, *, password: str | None) -> bytes:
    inner = _NATIVE_MAGIC + len(payload).to_bytes(4, "big") + zlib.crc32(payload).to_bytes(4, "big") + payload
    if password is None:
        return inner
    return _PASSWORD_MAGIC + _xor_password(inner, password)


def _unframe_payload(data: bytes, *, password: str | None) -> tuple[bytes, bool]:
    if password is not None:
        if not data.startswith(_PASSWORD_MAGIC):
            raise ValueError("不是本地 SpamMimic 密码帧")
        data = _xor_password(data[len(_PASSWORD_MAGIC) :], password)
        verified = True
    else:
        verified = False
    if not data.startswith(_NATIVE_MAGIC):
        raise ValueError("没有找到本地 SpamMimic 载荷帧")
    pos = len(_NATIVE_MAGIC)
    if len(data) < pos + 8:
        raise ValueError("SpamMimic 载荷帧不完整")
    size = int.from_bytes(data[pos : pos + 4], "big")
    checksum = int.from_bytes(data[pos + 4 : pos + 8], "big")
    payload = data[pos + 8 : pos + 8 + size]
    if len(payload) != size:
        raise ValueError("SpamMimic 载荷长度不足")
    if zlib.crc32(payload) != checksum:
        raise ValueError("SpamMimic 载荷校验失败")
    return payload, verified


def _encode_spam_native(bits: list[int]) -> str:
    phrases: list[str] = []
    for index in range(0, len(bits), 2):
        chunk = bits[index : index + 2]
        while len(chunk) < 2:
            chunk.append(0)
        value = (chunk[0] << 1) | chunk[1]
        phrases.append(_SPAM_GROUPS[(index // 2) % len(_SPAM_GROUPS)][value])
    paragraphs: list[str] = []
    for start in range(0, len(phrases), 12):
        paragraphs.append(fill(" ".join(phrases[start : start + 12]), width=72))
    return "\n\n".join(paragraphs) + "\n"


def _decode_spam_bits(text: str) -> list[int]:
    pos = 0
    group_index = 0
    bits: list[int] = []
    while True:
        group = _SPAM_GROUPS[group_index % len(_SPAM_GROUPS)]
        matches: list[tuple[int, int, int]] = []
        for value, phrase in enumerate(group):
            match = re.search(_phrase_regex(phrase), text[pos:], flags=re.IGNORECASE)
            if match:
                matches.append((pos + match.start(), value, pos + match.end()))
        if not matches:
            break
        _found, value, end = min(matches, key=lambda item: item[0])
        bits.extend([(value >> 1) & 1, value & 1])
        pos = end
        group_index += 1
    if len(bits) < (len(_NATIVE_MAGIC) + 8) * 8:
        raise ValueError("SpamMimic 文本中可识别的本地 grammar 片段不足")
    return bits


def _phrase_regex(phrase: str) -> str:
    return r"\s+".join(re.escape(part) for part in phrase.split())


def _encode_space_native(bits: list[int], cover: str) -> str:
    lines = cover.splitlines() or [""]
    out: list[str] = []
    bit_index = 0
    for line in lines:
        if bit_index < len(bits):
            chunk = bits[bit_index : bit_index + 8]
            bit_index += len(chunk)
            suffix = "".join(_SPACE_ONE if bit else _SPACE_ZERO for bit in chunk)
            out.append(line.rstrip(" \t") + suffix)
        else:
            out.append(line)
    while bit_index < len(bits):
        chunk = bits[bit_index : bit_index + 8]
        bit_index += len(chunk)
        out.append("".join(_SPACE_ONE if bit else _SPACE_ZERO for bit in chunk))
    return "\n".join(out) + "\n"


def _decode_space_bits(text: str) -> list[int]:
    bits: list[int] = []
    for line in text.splitlines():
        trailing = re.search(r"[ \t]+$", line)
        if not trailing:
            continue
        for char in trailing.group(0):
            bits.append(1 if char == _SPACE_ONE else 0)
    if len(bits) < (len(_NATIVE_MAGIC) + 8) * 8:
        raise ValueError("SpamMimic space 文本中可识别的本地空白数据不足")
    return bits


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in data for bit in range(7, -1, -1)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for index in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _xor_password(data: bytes, password: str) -> bytes:
    key = password.encode("utf-8")
    if not key:
        raise ValueError("SpamMimic 密码不能为空")
    out = bytearray()
    counter = 0
    offset = 0
    while offset < len(data):
        block = sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
        for byte in block:
            if offset == len(data):
                break
            out.append(data[offset] ^ byte)
            offset += 1
    return bytes(out)


def _load_payload(*, payload_path: Path | None, text: str | None) -> bytes:
    if payload_path is None and text is None:
        raise ValueError("需要 --text 或 --payload")
    if payload_path is not None and text is not None:
        raise ValueError("--text 与 --payload 只能二选一")
    if payload_path is not None:
        _check_file(payload_path, "载荷文件")
        return payload_path.read_bytes()
    return (text or "").encode("utf-8")


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")


def _validate_mode(mode: str) -> str:
    value = mode.lower()
    aliases = {"mail": "spam", "email": "spam", "spaces": "space"}
    value = aliases.get(value, value)
    if value not in {"spam", "space"}:
        raise ValueError("mode 必须是 spam 或 space")
    return value


def _validate_backend(backend: str, *, allow_auto: bool = False) -> str:
    value = backend.lower()
    allowed = {"native", "remote"}
    if allow_auto:
        allowed.add("auto")
    if value not in allowed:
        raise ValueError("backend 必须是 native、remote" + (" 或 auto" if allow_auto else ""))
    return value
