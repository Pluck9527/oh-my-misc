from __future__ import annotations

import base64
import itertools
from collections.abc import Iterator
from pathlib import Path

from oh_my_misc.archive_crack import ArchiveCrackResult, crack_archive_password_candidates

DEFAULT_INVISIBLE_CHARS = "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\u2064\ufeff"


def crack_invisible_archive_password(
    archive_path: Path,
    output_dir: Path | None = None,
    *,
    password_b64: list[str] | None = None,
    b64_file: Path | None = None,
    password_text: list[str] | None = None,
    text_file: Path | None = None,
    brute_raw: bool = False,
    min_bytes: int = 1,
    max_bytes: int = 2,
    zero_width: bool = False,
    min_chars: int = 1,
    max_chars: int = 2,
    zero_width_chars: str = DEFAULT_INVISIBLE_CHARS,
    encoding: str = "utf-8",
    backend: str = "auto",
    workers: int = 0,
    chunk_size: int = 4096,
    max_attempts: int | None = None,
    verify: bool = True,
    sevenzip: Path | None = None,
) -> ArchiveCrackResult:
    explicit_sources = any((password_b64, b64_file, password_text, text_file, zero_width))
    if not explicit_sources:
        brute_raw = True
    candidates = invisible_password_candidates(
        password_b64=password_b64 or [],
        b64_file=b64_file,
        password_text=password_text or [],
        text_file=text_file,
        brute_raw=brute_raw,
        min_bytes=min_bytes,
        max_bytes=max_bytes,
        zero_width=zero_width,
        min_chars=min_chars,
        max_chars=max_chars,
        zero_width_chars=zero_width_chars,
        encoding=encoding,
    )
    return crack_archive_password_candidates(
        archive_path,
        output_dir,
        candidates,
        backend=backend,
        workers=workers,
        chunk_size=chunk_size,
        max_attempts=max_attempts,
        verify=verify,
        sevenzip=sevenzip,
        encoding=encoding,
        operation="zip.invisible-password",
    )


def invisible_password_candidates(
    *,
    password_b64: list[str],
    b64_file: Path | None,
    password_text: list[str],
    text_file: Path | None,
    brute_raw: bool,
    min_bytes: int,
    max_bytes: int,
    zero_width: bool,
    min_chars: int,
    max_chars: int,
    zero_width_chars: str,
    encoding: str,
) -> Iterator[bytes]:
    seen: set[bytes] = set()
    for candidate in _base64_candidates(password_b64, b64_file):
        if candidate not in seen:
            seen.add(candidate)
            yield candidate
    for candidate in _text_candidates(password_text, text_file, encoding=encoding):
        if candidate not in seen:
            seen.add(candidate)
            yield candidate
    if zero_width:
        _validate_range(min_chars, max_chars, "字符")
        chars = list(dict.fromkeys(zero_width_chars))
        if not chars:
            raise ValueError("zero_width_chars 不能为空")
        for length in range(min_chars, max_chars + 1):
            for item in itertools.product(chars, repeat=length):
                candidate = "".join(item).encode(encoding)
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate
    if brute_raw:
        _validate_range(min_bytes, max_bytes, "字节")
        for length in range(min_bytes, max_bytes + 1):
            for item in itertools.product(range(256), repeat=length):
                candidate = bytes(item)
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def _base64_candidates(values: list[str], file_path: Path | None) -> Iterator[bytes]:
    for value in values:
        yield _decode_base64_password(value)
    if file_path is not None:
        _check_file(file_path, "Base64 密码文件")
        for line in file_path.read_text(encoding="utf-8").splitlines():
            cleaned = line.strip()
            if cleaned:
                yield _decode_base64_password(cleaned)


def _text_candidates(
    values: list[str], file_path: Path | None, *, encoding: str
) -> Iterator[bytes]:
    for value in values:
        yield value.encode(encoding)
    if file_path is not None:
        _check_file(file_path, "密码文本文件")
        for line in file_path.read_text(encoding="utf-8").splitlines():
            if line:
                yield line.encode(encoding)


def _decode_base64_password(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as error:
        raise ValueError(f"Base64 密码解码失败：{value}") from error


def _validate_range(min_value: int, max_value: int, label: str) -> None:
    if min_value < 0 or max_value < min_value:
        raise ValueError(f"{label}长度范围无效")


def _check_file(path: Path, label: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
