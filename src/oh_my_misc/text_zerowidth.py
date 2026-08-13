from __future__ import annotations

import math
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_CHARS = "\u200c\u200d\u202c\ufeff"
PRESET_CHARS = {
    "330k": DEFAULT_CHARS,
    "default": DEFAULT_CHARS,
    "all4": "\u200b\u200c\u200d\ufeff",
    "zwsp-bit": "\u200b\u200c",
    "joiner-bit": "\u200c\u200d",
    "separator-bit": "\u200c\u2063",
}
ZERO_WIDTH_CHARS = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2060",  # WORD JOINER
    "\u2061",  # FUNCTION APPLICATION
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
}


@dataclass(frozen=True)
class ZeroWidthResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    alphabet: str
    chars: list[str]
    char_codes: list[str]
    hidden_chars: int = 0
    visible_chars: int = 0
    payload_bytes: int = 0
    payload_text_length: int = 0
    written_bytes: int = 0
    counts: dict[str, int] | None = None
    preview: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def hide_zero_width(
    input_path: Path,
    output_path: Path,
    *,
    payload_path: Path | None = None,
    text: str | None = None,
    mode: str = "binary",
    chars: str | None = None,
    alphabet: str = "330k",
    placement: str = "spread",
) -> ZeroWidthResult:
    _check_file(input_path, "载体文本")
    use_chars, alphabet_name = resolve_chars(chars=chars, alphabet=alphabet)
    _validate_mode(mode)
    payload_bytes, payload_text = _load_payload(payload_path=payload_path, text=text)
    cover = input_path.read_text(encoding="utf-8")
    hidden = (
        encode_zero_width_binary(payload_bytes, use_chars)
        if mode == "binary"
        else encode_zero_width_text(payload_text, use_chars)
    )
    stego = insert_zero_width(cover, hidden, mode=mode, placement=placement, radix=len(use_chars))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(stego, encoding="utf-8")
    return ZeroWidthResult(
        operation="text.zerowidth.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode=mode,
        alphabet=alphabet_name,
        chars=list(use_chars),
        char_codes=[_char_code(ch) for ch in use_chars],
        hidden_chars=len(hidden),
        visible_chars=len(strip_zero_width(stego)),
        payload_bytes=len(payload_bytes),
        payload_text_length=len(payload_text),
        written_bytes=output_path.stat().st_size,
    )


def extract_zero_width(
    input_path: Path,
    output_path: Path,
    *,
    mode: str = "binary",
    chars: str | None = None,
    alphabet: str = "330k",
) -> ZeroWidthResult:
    _check_file(input_path, "零宽字符文本")
    use_chars, alphabet_name = resolve_chars(chars=chars, alphabet=alphabet)
    _validate_mode(mode)
    data = input_path.read_text(encoding="utf-8")
    hidden = collect_zero_width(data, use_chars)
    if mode == "binary":
        payload = decode_zero_width_binary(hidden, use_chars)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
        payload_bytes = len(payload)
        payload_text_length = 0
        preview = payload[:80].decode("utf-8", errors="replace")
    else:
        decoded_text = decode_zero_width_text(hidden, use_chars)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(decoded_text, encoding="utf-8")
        payload_bytes = len(decoded_text.encode("utf-8"))
        payload_text_length = len(decoded_text)
        preview = decoded_text[:80]
    return ZeroWidthResult(
        operation="text.zerowidth.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode=mode,
        alphabet=alphabet_name,
        chars=list(use_chars),
        char_codes=[_char_code(ch) for ch in use_chars],
        hidden_chars=len(hidden),
        visible_chars=len(strip_zero_width(data)),
        payload_bytes=payload_bytes,
        payload_text_length=payload_text_length,
        written_bytes=output_path.stat().st_size,
        preview=preview,
    )


def inspect_zero_width(input_path: Path) -> ZeroWidthResult:
    _check_file(input_path, "文本")
    data = input_path.read_text(encoding="utf-8")
    counts: dict[str, int] = {}
    for ch in data:
        if ch in ZERO_WIDTH_CHARS:
            label = f"{_char_code(ch)} {unicodedata.name(ch, 'UNKNOWN')}"
            counts[label] = counts.get(label, 0) + 1
    hidden = "".join(ch for ch in data if ch in ZERO_WIDTH_CHARS)
    return ZeroWidthResult(
        operation="text.zerowidth.inspect",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        mode="inspect",
        alphabet="known-zero-width",
        chars=sorted(set(hidden)),
        char_codes=[_char_code(ch) for ch in sorted(set(hidden))],
        hidden_chars=len(hidden),
        visible_chars=len(strip_zero_width(data)),
        counts=counts,
        preview=visualize_zero_width(data[:500]),
    )


def strip_zero_width_file(input_path: Path, output_path: Path) -> ZeroWidthResult:
    _check_file(input_path, "文本")
    data = input_path.read_text(encoding="utf-8")
    stripped = strip_zero_width(data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(stripped, encoding="utf-8")
    return ZeroWidthResult(
        operation="text.zerowidth.strip",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode="strip",
        alphabet="known-zero-width",
        chars=[],
        char_codes=[],
        hidden_chars=len(data) - len(stripped),
        visible_chars=len(stripped),
        written_bytes=output_path.stat().st_size,
    )


def encode_zero_width_binary(data: bytes, chars: str = DEFAULT_CHARS) -> str:
    codelength = _code_length(256, len(chars))
    return _digits_to_chars((_to_base(byte, len(chars), codelength) for byte in data), chars)


def decode_zero_width_binary(hidden: str, chars: str = DEFAULT_CHARS) -> bytes:
    codelength = _code_length(256, len(chars))
    digits = _chars_to_digits(hidden, chars)
    out = bytearray()
    for index in range(0, len(digits) - (len(digits) % codelength), codelength):
        out.append(int(digits[index : index + codelength], len(chars)))
    return bytes(out)


def encode_zero_width_text(text: str, chars: str = DEFAULT_CHARS) -> str:
    codelength = _code_length(65536, len(chars))
    data = text.encode("utf-16-be", errors="surrogatepass")
    units = (int.from_bytes(data[index : index + 2], "big") for index in range(0, len(data), 2))
    return _digits_to_chars((_to_base(unit, len(chars), codelength) for unit in units), chars)


def decode_zero_width_text(hidden: str, chars: str = DEFAULT_CHARS) -> str:
    codelength = _code_length(65536, len(chars))
    digits = _chars_to_digits(hidden, chars)
    data = bytearray()
    for index in range(0, len(digits) - (len(digits) % codelength), codelength):
        value = int(digits[index : index + codelength], len(chars))
        data.extend(value.to_bytes(2, "big"))
    return bytes(data).decode("utf-16-be", errors="surrogatepass")


def insert_zero_width(
    cover: str, hidden: str, *, mode: str = "binary", placement: str = "spread", radix: int = 4
) -> str:
    if placement not in {"spread", "start", "end"}:
        raise ValueError("placement 必须是 spread、start 或 end")
    if placement == "start":
        return hidden + cover
    if placement == "end" or not cover:
        return cover + hidden
    unit_size = _code_length(256 if mode == "binary" else 65536, radix)
    chunks = [hidden[index : index + unit_size] for index in range(0, len(hidden), unit_size)]
    if not chunks:
        return cover
    out: list[str] = []
    chunk_index = 0
    for ch in cover:
        out.append(ch)
        if chunk_index < len(chunks):
            out.append(chunks[chunk_index])
            chunk_index += 1
    if chunk_index < len(chunks):
        out.extend(chunks[chunk_index:])
    return "".join(out)


def collect_zero_width(data: str, chars: str = DEFAULT_CHARS) -> str:
    allowed = set(chars)
    return "".join(ch for ch in data if ch in allowed)


def strip_zero_width(data: str) -> str:
    return "".join(ch for ch in data if ch not in ZERO_WIDTH_CHARS)


def visualize_zero_width(data: str) -> str:
    mapping = {
        "\u200b": "<U+200B>",
        "\u200c": "<U+200C>",
        "\u200d": "<U+200D>",
        "\u200e": "<U+200E>",
        "\u200f": "<U+200F>",
        "\u202a": "<U+202A>",
        "\u202b": "<U+202B>",
        "\u202c": "<U+202C>",
        "\u202d": "<U+202D>",
        "\u202e": "<U+202E>",
        "\u2060": "<U+2060>",
        "\u2061": "<U+2061>",
        "\u2062": "<U+2062>",
        "\u2063": "<U+2063>",
        "\u2064": "<U+2064>",
        "\u2066": "<U+2066>",
        "\u2067": "<U+2067>",
        "\u2068": "<U+2068>",
        "\u2069": "<U+2069>",
        "\ufeff": "<U+FEFF>",
    }
    return "".join(mapping.get(ch, ch) for ch in data)


def resolve_chars(*, chars: str | None, alphabet: str) -> tuple[str, str]:
    if chars is not None:
        parsed = parse_chars(chars)
        _validate_chars(parsed)
        return parsed, "custom"
    if alphabet not in PRESET_CHARS:
        raise ValueError(f"alphabet 必须是 {', '.join(sorted(PRESET_CHARS))} 或提供 --chars")
    parsed = PRESET_CHARS[alphabet]
    _validate_chars(parsed)
    return parsed, alphabet


def parse_chars(value: str) -> str:
    if "," in value:
        return "".join(_parse_char_token(part.strip()) for part in value.split(",") if part.strip())
    if value.startswith(("U+", "u+", "\\u")):
        return _parse_char_token(value)
    return value.encode("utf-8").decode("unicode_escape") if "\\" in value else value


def _parse_char_token(token: str) -> str:
    token = token.strip()
    if token.upper().startswith("U+"):
        return chr(int("0x" + token[2:], base=0))
    if token.startswith(("\\u", "\\U")):
        return token.encode("utf-8").decode("unicode_escape")
    if len(token) == 1:
        return token
    raise ValueError(f"无法解析零宽字符 token：{token}")


def _validate_chars(chars: str) -> None:
    if len(chars) < 2:
        raise ValueError("零宽字符表至少需要 2 个字符")
    if len(set(chars)) != len(chars):
        raise ValueError("零宽字符表不能包含重复字符")
    if len(chars) > 10:
        raise ValueError("零宽字符表最多支持 10 个字符")


def _validate_mode(mode: str) -> None:
    if mode not in {"binary", "text"}:
        raise ValueError("mode 必须是 binary 或 text")


def _code_length(values: int, radix: int) -> int:
    return math.ceil(math.log(values) / math.log(radix))


def _to_base(value: int, radix: int, width: int) -> str:
    digits = []
    current = value
    for _ in range(width):
        digits.append(str(current % radix))
        current //= radix
    return "".join(reversed(digits))


def _digits_to_chars(chunks: object, chars: str) -> str:
    table = {str(index): ch for index, ch in enumerate(chars)}
    return "".join(table[digit] for chunk in chunks for digit in chunk)


def _chars_to_digits(hidden: str, chars: str) -> str:
    table = {ch: str(index) for index, ch in enumerate(chars)}
    return "".join(table[ch] for ch in hidden if ch in table)


def _load_payload(*, payload_path: Path | None, text: str | None) -> tuple[bytes, str]:
    if payload_path is None and text is None:
        raise ValueError("zerowidth hide 需要 --payload 或 --text")
    if payload_path is not None and text is not None:
        raise ValueError("zerowidth hide 只能指定 --payload 或 --text 之一")
    if payload_path is not None:
        _check_file(payload_path, "载荷文件")
        data = payload_path.read_bytes()
        return data, data.decode("utf-8", errors="surrogateescape")
    assert text is not None
    return text.encode("utf-8"), text


def _char_code(ch: str) -> str:
    return f"U+{ord(ch):04X}"


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
