from __future__ import annotations

import binascii
import itertools
import math
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

CRC32_POLY = 0xEDB88320
BYTE_ALPHABETS = {
    "all": bytes(range(256)),
    "printable": bytes(range(0x20, 0x7F)),
    "ascii": bytes(range(0x80)),
    "digits": b"0123456789",
    "lower": b"abcdefghijklmnopqrstuvwxyz",
    "upper": b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha": b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum": b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "hex": b"0123456789abcdefABCDEF",
    "flag": b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_-=!@#$%^&*()+[]:;,.?/",
}


@dataclass(frozen=True)
class ZipEntryInfo:
    filename: str
    crc32: str
    file_size: int
    compress_size: int
    compress_type: int
    encrypted: bool


@dataclass(frozen=True)
class ZipCrcResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    crc32: str
    length: int
    entry: str
    charset: str
    charset_size: int
    prefix_hex: str = ""
    suffix_hex: str = ""
    candidates: int = 0
    truncated: bool = False
    attempts: int = 0
    candidate_hex: list[str] | None = None
    candidate_text: list[str] | None = None
    entries: list[dict[str, object]] | None = None
    written_bytes: int = 0
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def list_zip_crc(zip_path: Path) -> ZipCrcResult:
    _check_file(zip_path, "ZIP 文件")
    entries = [_entry_to_info(info) for info in _zip_infos(zip_path)]
    return ZipCrcResult(
        operation="zip.crc.list",
        input_path=str(zip_path),
        output_path="-",
        output_paths=[],
        crc32="-",
        length=0,
        entry="-",
        charset="-",
        charset_size=0,
        entries=[asdict(entry) for entry in entries],
        count=len(entries),
    )


def brute_zip_crc(
    zip_path: Path,
    output_path: Path | None = None,
    *,
    entry: str | None = None,
    charset: str = "all",
    chars: str | None = None,
    prefix: str = "",
    suffix: str = "",
    prefix_hex: str = "",
    suffix_hex: str = "",
    limit: int = 100,
    max_prefixes: int = 2_000_000,
) -> ZipCrcResult:
    _check_file(zip_path, "ZIP 文件")
    info = _select_zip_info(zip_path, entry)
    candidates, attempts, truncated, charset_bytes, charset_label, prefix_bytes, suffix_bytes = (
        reverse_crc32(
            info.CRC,
            info.file_size,
            charset=charset,
            chars=chars,
            prefix=prefix,
            suffix=suffix,
            prefix_hex=prefix_hex,
            suffix_hex=suffix_hex,
            limit=limit,
            max_prefixes=max_prefixes,
        )
    )
    output_paths, written = _write_candidates(candidates, output_path)
    return ZipCrcResult(
        operation="zip.crc.brute",
        input_path=str(zip_path),
        output_path=str(output_path) if output_path is not None else "-",
        output_paths=output_paths,
        crc32=f"0x{info.CRC:08x}",
        length=info.file_size,
        entry=info.filename,
        charset=charset_label,
        charset_size=len(charset_bytes),
        prefix_hex=prefix_bytes.hex(),
        suffix_hex=suffix_bytes.hex(),
        candidates=len(candidates),
        truncated=truncated,
        attempts=attempts,
        candidate_hex=[candidate.hex() for candidate in candidates[: min(len(candidates), 20)]],
        candidate_text=[
            _preview(candidate) for candidate in candidates[: min(len(candidates), 20)]
        ],
        written_bytes=written,
    )


def reverse_crc32_direct(
    crc32_value: int,
    length: int,
    output_path: Path | None = None,
    *,
    charset: str = "all",
    chars: str | None = None,
    prefix: str = "",
    suffix: str = "",
    prefix_hex: str = "",
    suffix_hex: str = "",
    limit: int = 100,
    max_prefixes: int = 2_000_000,
) -> ZipCrcResult:
    candidates, attempts, truncated, charset_bytes, charset_label, prefix_bytes, suffix_bytes = (
        reverse_crc32(
            crc32_value,
            length,
            charset=charset,
            chars=chars,
            prefix=prefix,
            suffix=suffix,
            prefix_hex=prefix_hex,
            suffix_hex=suffix_hex,
            limit=limit,
            max_prefixes=max_prefixes,
        )
    )
    output_paths, written = _write_candidates(candidates, output_path)
    return ZipCrcResult(
        operation="zip.crc.reverse",
        input_path="-",
        output_path=str(output_path) if output_path is not None else "-",
        output_paths=output_paths,
        crc32=f"0x{crc32_value & 0xFFFFFFFF:08x}",
        length=length,
        entry="-",
        charset=charset_label,
        charset_size=len(charset_bytes),
        prefix_hex=prefix_bytes.hex(),
        suffix_hex=suffix_bytes.hex(),
        candidates=len(candidates),
        truncated=truncated,
        attempts=attempts,
        candidate_hex=[candidate.hex() for candidate in candidates[: min(len(candidates), 20)]],
        candidate_text=[
            _preview(candidate) for candidate in candidates[: min(len(candidates), 20)]
        ],
        written_bytes=written,
    )


def reverse_crc32(
    crc32_value: int,
    length: int,
    *,
    charset: str = "all",
    chars: str | None = None,
    prefix: str = "",
    suffix: str = "",
    prefix_hex: str = "",
    suffix_hex: str = "",
    limit: int = 100,
    max_prefixes: int = 2_000_000,
) -> tuple[list[bytes], int, bool, bytes, str, bytes, bytes]:
    if length < 0:
        raise ValueError("length 必须大于等于 0")
    if limit < 1:
        raise ValueError("limit 必须大于等于 1")
    charset_bytes, charset_label = resolve_charset(charset=charset, chars=chars)
    charset_set = set(charset_bytes)
    prefix_bytes = _parse_known_bytes(prefix, prefix_hex, "prefix")
    suffix_bytes = _parse_known_bytes(suffix, suffix_hex, "suffix")
    if len(prefix_bytes) + len(suffix_bytes) > length:
        raise ValueError("prefix + suffix 长度不能超过目标 length")
    constraints = _known_constraints(length, prefix_bytes, suffix_bytes)
    crc32_value &= 0xFFFFFFFF
    if length == 0:
        candidate = b""
        return (
            ([candidate] if _crc32(candidate) == crc32_value else []),
            1,
            False,
            charset_bytes,
            charset_label,
            prefix_bytes,
            suffix_bytes,
        )
    if length < 4:
        return _brute_short(
            crc32_value,
            length,
            constraints,
            charset_bytes,
            charset_label,
            prefix_bytes,
            suffix_bytes,
            limit,
        )
    table, reverse_table = _crc_tables()
    choices = [
        _choices_for_position(index, constraints, charset_bytes, charset_set)
        for index in range(length - 4)
    ]
    total_prefixes = math.prod(len(choice) for choice in choices) if choices else 1
    if max_prefixes and total_prefixes > max_prefixes:
        raise ValueError(
            f"需要枚举 {total_prefixes} 个前缀，超过 --max-prefixes {max_prefixes}；请缩小 --charset/--prefix/--suffix 或调大限制"
        )
    candidates: list[bytes] = []
    attempts = 0
    truncated = False
    for prefix_tuple in itertools.product(*choices) if choices else ((),):
        attempts += 1
        head = bytes(prefix_tuple)
        accum = _crc32_table(head, table)
        for tail_tuple in _find_reverse_tail(crc32_value, accum, table, reverse_table):
            candidate = head + bytes(tail_tuple)
            if (
                _candidate_matches(candidate, constraints, charset_set)
                and _crc32(candidate) == crc32_value
            ):
                candidates.append(candidate)
                if len(candidates) >= limit:
                    truncated = True
                    return (
                        candidates,
                        attempts,
                        truncated,
                        charset_bytes,
                        charset_label,
                        prefix_bytes,
                        suffix_bytes,
                    )
    return candidates, attempts, truncated, charset_bytes, charset_label, prefix_bytes, suffix_bytes


def resolve_charset(*, charset: str, chars: str | None) -> tuple[bytes, str]:
    if chars is not None:
        parsed = _parse_chars(chars)
        if not parsed:
            raise ValueError("--chars 不能为空")
        return bytes(dict.fromkeys(parsed)), "custom"
    if charset not in BYTE_ALPHABETS:
        raise ValueError(f"charset 必须是 {', '.join(sorted(BYTE_ALPHABETS))} 或提供 --chars")
    return BYTE_ALPHABETS[charset], charset


def parse_crc32(value: str) -> int:
    text = value.strip().lower()
    text = text.removeprefix("crc32:")
    if text.startswith("0x"):
        number = int(text, 16)
    else:
        number = int(text, 16 if any(ch in text for ch in "abcdef") else 10)
    if not 0 <= number <= 0xFFFFFFFF:
        raise ValueError(f"CRC32 超出范围：{value}")
    return number


def _brute_short(
    crc32_value: int,
    length: int,
    constraints: dict[int, int],
    charset_bytes: bytes,
    charset_label: str,
    prefix_bytes: bytes,
    suffix_bytes: bytes,
    limit: int,
) -> tuple[list[bytes], int, bool, bytes, str, bytes, bytes]:
    charset_set = set(charset_bytes)
    choices = [
        _choices_for_position(index, constraints, charset_bytes, charset_set)
        for index in range(length)
    ]
    candidates: list[bytes] = []
    attempts = 0
    truncated = False
    for item in itertools.product(*choices):
        attempts += 1
        candidate = bytes(item)
        if _crc32(candidate) == crc32_value:
            candidates.append(candidate)
            if len(candidates) >= limit:
                truncated = True
                break
    return candidates, attempts, truncated, charset_bytes, charset_label, prefix_bytes, suffix_bytes


def _find_reverse_tail(
    desired: int,
    accum: int,
    table: list[int],
    reverse_table: list[tuple[int, ...]],
) -> set[tuple[int, int, int, int]]:
    solutions: set[tuple[int, int, int, int]] = set()
    initial = ~accum
    stack: list[tuple[int, ...]] = [(~desired,)]
    while stack:
        node = stack.pop()
        for index in reverse_table[(node[0] >> 24) & 0xFF]:
            if len(node) == 4:
                state = initial
                data: list[int] = []
                expanded = node[1:] + (index,)
                for pos in range(3, -1, -1):
                    data.append((state ^ expanded[pos]) & 0xFF)
                    state >>= 8
                    state ^= table[expanded[pos]]
                solutions.add(tuple(data))  # type: ignore[arg-type]
            else:
                stack.append(((node[0] ^ table[index]) << 8,) + node[1:] + (index,))
    return solutions


def _crc_tables() -> tuple[list[int], list[tuple[int, ...]]]:
    table: list[int] = []
    for value in range(256):
        current = value
        for _ in range(8):
            if current & 1:
                current = (current >> 1) ^ CRC32_POLY
            else:
                current >>= 1
        table.append(current)
    reverse_table = [
        tuple(index for index in range(256) if table[index] >> 24 == high) for high in range(256)
    ]
    return table, reverse_table


def _crc32_table(data: bytes, table: list[int], accum: int = 0) -> int:
    value = ~accum
    for byte in data:
        value = table[(value ^ byte) & 0xFF] ^ ((value >> 8) & 0x00FFFFFF)
    return (~value) & 0xFFFFFFFF


def _crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def _known_constraints(length: int, prefix: bytes, suffix: bytes) -> dict[int, int]:
    constraints: dict[int, int] = {}
    for index, byte in enumerate(prefix):
        constraints[index] = byte
    start = length - len(suffix)
    for offset, byte in enumerate(suffix):
        index = start + offset
        if index in constraints and constraints[index] != byte:
            raise ValueError("prefix 与 suffix 约束冲突")
        constraints[index] = byte
    return constraints


def _choices_for_position(
    index: int, constraints: dict[int, int], charset: bytes, charset_set: set[int]
) -> bytes:
    if index not in constraints:
        return charset
    value = constraints[index]
    if value not in charset_set:
        raise ValueError(f"已知字节 0x{value:02x} 不在当前字符集里")
    return bytes([value])


def _candidate_matches(
    candidate: bytes, constraints: dict[int, int], charset_set: set[int]
) -> bool:
    return all(candidate[index] == value for index, value in constraints.items()) and all(
        byte in charset_set for byte in candidate
    )


def _parse_known_bytes(text: str, hex_text: str, label: str) -> bytes:
    if text and hex_text:
        raise ValueError(f"--{label} 与 --{label}-hex 只能指定一个")
    if hex_text:
        cleaned = hex_text.replace(" ", "").replace(":", "")
        if len(cleaned) % 2:
            raise ValueError(f"--{label}-hex 长度必须为偶数")
        return bytes.fromhex(cleaned)
    return text.encode("utf-8")


def _parse_chars(value: str) -> bytes:
    if value.startswith("hex:"):
        return bytes.fromhex(value[4:].replace(" ", "").replace(":", ""))
    return value.encode("utf-8")


def _zip_infos(zip_path: Path) -> list[zipfile.ZipInfo]:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            return archive.infolist()
    except zipfile.BadZipFile as error:
        raise ValueError(f"ZIP 解析失败：{error}") from error


def _select_zip_info(zip_path: Path, entry: str | None) -> zipfile.ZipInfo:
    infos = [info for info in _zip_infos(zip_path) if not info.is_dir()]
    if not infos:
        raise ValueError("ZIP 中没有普通文件条目")
    if entry is None:
        if len(infos) != 1:
            names = ", ".join(info.filename for info in infos[:8])
            raise ValueError(f"ZIP 中有 {len(infos)} 个文件，请用 --entry 指定：{names}")
        return infos[0]
    for info in infos:
        if info.filename == entry:
            return info
    raise ValueError(f"ZIP 中找不到条目：{entry}")


def _entry_to_info(info: zipfile.ZipInfo) -> ZipEntryInfo:
    return ZipEntryInfo(
        filename=info.filename,
        crc32=f"0x{info.CRC:08x}",
        file_size=info.file_size,
        compress_size=info.compress_size,
        compress_type=info.compress_type,
        encrypted=bool(info.flag_bits & 0x1),
    )


def _write_candidates(candidates: list[bytes], output_path: Path | None) -> tuple[list[str], int]:
    if output_path is None or not candidates:
        return [], 0
    if len(candidates) == 1:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(candidates[0])
        return [str(output_path)], len(candidates[0])
    output_path.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    total = 0
    width = max(3, len(str(len(candidates) - 1)))
    for index, candidate in enumerate(candidates):
        path = output_path / f"candidate_{index:0{width}d}.bin"
        path.write_bytes(candidate)
        paths.append(str(path))
        total += len(candidate)
    return paths, total


def _preview(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
