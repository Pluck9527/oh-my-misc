from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

from PIL import Image

MAX_MESSAGE_SIZE = 1000


@dataclass(frozen=True)
class PixelJihadDecodedMessage:
    input_path: str
    width: int
    height: int
    raw: str
    text: str
    encrypted: bool
    status: str


@dataclass(frozen=True)
class PixelJihadDecodeResult:
    operation: str
    output_path: str | None
    input_paths: list[str]
    output_paths: list[str]
    messages: list[dict[str, object]]
    text: str
    raw_text: str
    count: int
    found_password: str | None = None
    attempts: int = 0

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class PixelJihadEncodeResult:
    operation: str
    input_path: str
    output_path: str
    width: int
    height: int
    message_size: int
    max_message_size: int
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def decode_pixeljihad_images(
    input_paths: list[Path],
    *,
    password: str = "",
    output_path: Path | None = None,
    raw: bool = False,
    found_password: str | None = None,
    attempts: int = 0,
) -> PixelJihadDecodeResult:
    """Decode one or more PixelJihad images with the supplied location password.

    PixelJihad's empty-password mode stores a JSON object shaped like
    {"text":"..."}. If a password-protected sample is supplied, this decoder
    returns the embedded SJCL JSON ciphertext in ``raw``; decrypting that SJCL
    payload is intentionally left as a separate step.
    """

    if not input_paths:
        raise ValueError("至少需要一张输入图片")
    messages: list[PixelJihadDecodedMessage] = []
    for input_path in sorted(input_paths, key=_natural_sort_key):
        if not input_path.is_file():
            raise FileNotFoundError(f"文件不存在：{input_path}")
        with Image.open(input_path) as source:
            image = source.convert("RGBA")
            raw_message = decode_pixeljihad_bytes(image.tobytes(), password=password)
            text, encrypted, status = _message_text(raw_message)
            messages.append(
                PixelJihadDecodedMessage(
                    input_path=str(input_path),
                    width=image.width,
                    height=image.height,
                    raw=raw_message,
                    text=text,
                    encrypted=encrypted,
                    status=status,
                )
            )

    selected_parts = [message.raw if raw else (message.text or message.raw) for message in messages]
    raw_parts = [message.raw for message in messages]
    joined = "".join(selected_parts)
    raw_joined = "".join(raw_parts)
    outputs: list[str] = []
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(joined, encoding="utf-8")
        outputs.append(str(output_path))
    return PixelJihadDecodeResult(
        operation="image.pixeljihad.decode",
        output_path=str(output_path) if output_path is not None else None,
        input_paths=[str(path) for path in sorted(input_paths, key=_natural_sort_key)],
        output_paths=outputs,
        messages=[asdict(message) for message in messages],
        text=joined,
        raw_text=raw_joined,
        count=len(messages),
        found_password=found_password,
        attempts=attempts,
    )


def brute_pixeljihad_images(
    input_paths: list[Path],
    wordlist_path: Path,
    *,
    output_path: Path | None = None,
    raw: bool = False,
    contains: str | None = None,
) -> PixelJihadDecodeResult:
    """Try one PixelJihad location password per wordlist line and return the first hit."""

    if not wordlist_path.is_file():
        raise FileNotFoundError(f"字典不存在：{wordlist_path}")
    attempts = 0
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            attempts += 1
            result = decode_pixeljihad_images(
                input_paths,
                password=candidate,
                raw=raw,
                found_password=candidate,
                attempts=attempts,
            )
            candidate_text = result.text if not raw else result.raw_text
            has_payload = any(message["status"] != "empty" for message in result.messages)
            if not has_payload:
                continue
            if contains is not None and contains not in candidate_text:
                continue
            if output_path is not None:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(candidate_text, encoding="utf-8")
                result = PixelJihadDecodeResult(
                    operation=result.operation,
                    output_path=str(output_path),
                    input_paths=result.input_paths,
                    output_paths=[str(output_path)],
                    messages=result.messages,
                    text=result.text,
                    raw_text=result.raw_text,
                    count=result.count,
                    found_password=candidate,
                    attempts=attempts,
                )
            return result
    raise ValueError(f"字典爆破失败，尝试 {attempts} 个密码")


def encode_pixeljihad_image(
    input_path: Path,
    output_path: Path,
    text: str,
    *,
    password: str = "",
) -> PixelJihadEncodeResult:
    """Embed text using PixelJihad's empty-password JSON payload format."""

    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if password:
        raise ValueError("当前仅支持 PixelJihad 空密码嵌入；有密码样本可用 decode 提取 SJCL 密文")
    payload = json.dumps({"text": text}, ensure_ascii=False, separators=(",", ":"))
    message_units = _string_to_code_units(payload)
    if len(message_units) > MAX_MESSAGE_SIZE:
        raise ValueError(f"消息过长：{len(message_units)} > {MAX_MESSAGE_SIZE}")
    with Image.open(input_path) as source:
        image = source.convert("RGBA")
    colors = bytearray(image.tobytes())
    capacity_bits = int(len(colors) * 0.75)
    required_bits = (len(message_units) + 1) * 16
    if required_bits > capacity_bits:
        raise ValueError(f"图片容量不足：需要 {required_bits} bits，可用约 {capacity_bits} bits")
    encode_pixeljihad_bytes(colors, payload, password=password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    Image.frombytes("RGBA", image.size, bytes(colors)).save(output_path)
    return PixelJihadEncodeResult(
        operation="image.pixeljihad.encode",
        input_path=str(input_path),
        output_path=str(output_path),
        width=image.width,
        height=image.height,
        message_size=len(message_units),
        max_message_size=MAX_MESSAGE_SIZE,
    )


def decode_pixeljihad_bytes(
    colors: bytes,
    *,
    password: str = "",
    max_message_size: int = MAX_MESSAGE_SIZE,
) -> str:
    hash_words = _sha256_words_int32(password)
    used = bytearray(len(colors))
    pos = 0
    message_size, pos = _get_number_from_bits(colors, hash_words, used, pos)
    if ((message_size + 1) * 16) > (len(colors) * 0.75):
        return ""
    if message_size == 0 or message_size > max_message_size:
        return ""
    code_units: list[int] = []
    for _ in range(message_size):
        code_unit, pos = _get_number_from_bits(colors, hash_words, used, pos)
        code_units.append(code_unit)
    return _code_units_to_string(code_units)


def encode_pixeljihad_bytes(colors: bytearray, message: str, *, password: str = "") -> None:
    hash_words = _sha256_words_int32(password)
    code_units = _string_to_code_units(message)
    bits = _bits_from_number(len(code_units))
    for code_unit in code_units:
        bits.extend(_bits_from_number(code_unit))
    used = bytearray(len(colors))
    pos = 0
    for bit in bits:
        loc, pos = _get_next_location(pos, used, hash_words, len(colors))
        colors[loc] = (colors[loc] & 0xFE) | bit
        alpha_loc = loc
        while (alpha_loc + 1) % 4 != 0:
            alpha_loc += 1
        colors[alpha_loc] = 255


def _sha256_words_int32(password: str) -> list[int]:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return [struct.unpack(">i", digest[index : index + 4])[0] for index in range(0, 32, 4)]


def _get_next_location(
    pos: int,
    used: bytearray,
    hash_words: list[int],
    total: int,
) -> tuple[int, int]:
    loc = abs(hash_words[pos % len(hash_words)] * (pos + 1)) % total
    while True:
        if loc >= total:
            loc = 0
        elif used[loc] or (loc + 1) % 4 == 0:
            loc += 1
        else:
            used[loc] = 1
            return loc, pos + 1


def _get_number_from_bits(
    colors: bytes,
    hash_words: list[int],
    used: bytearray,
    pos: int,
) -> tuple[int, int]:
    number = 0
    for bitpos in range(16):
        loc, pos = _get_next_location(pos, used, hash_words, len(colors))
        bit = colors[loc] & 1
        number = (number & ~(1 << bitpos)) | (bit << bitpos)
    return number, pos


def _bits_from_number(number: int) -> list[int]:
    return [(number >> location) & 1 for location in range(16)]


def _string_to_code_units(text: str) -> list[int]:
    data = text.encode("utf-16-le", "surrogatepass")
    return [int.from_bytes(data[index : index + 2], "little") for index in range(0, len(data), 2)]


def _code_units_to_string(code_units: list[int]) -> str:
    data = b"".join(code_unit.to_bytes(2, "little") for code_unit in code_units)
    return data.decode("utf-16-le", "surrogatepass")


def _message_text(raw_message: str) -> tuple[str, bool, str]:
    if not raw_message:
        return "", False, "empty"
    try:
        payload = json.loads(raw_message)
    except json.JSONDecodeError:
        return "", False, "raw"
    if isinstance(payload, dict) and "text" in payload:
        return str(payload["text"]), False, "text"
    if isinstance(payload, dict) and "ct" in payload:
        return "", True, "sjcl-ciphertext"
    return "", False, "json"


def _natural_sort_key(path: Path) -> list[object]:
    import re

    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", path.name)]
