from __future__ import annotations

import itertools
import lzma
import os
import tempfile
import time
import zipfile
import zlib
from collections.abc import Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import asdict, dataclass
from pathlib import Path

import py7zr
from py7zr import exceptions as py7zr_exceptions

from oh_my_misc.zip_crc import BYTE_ALPHABETS


def _build_zipcrc_table() -> tuple[int, ...]:
    table: list[int] = []
    for value in range(256):
        current = value
        for _ in range(8):
            current = (current >> 1) ^ 0xEDB88320 if current & 1 else current >> 1
        table.append(current & 0xFFFFFFFF)
    return tuple(table)


_ZIPCRC_TABLE = _build_zipcrc_table()


@dataclass(frozen=True)
class ArchiveCrackResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    backend: str
    archive_format: str
    encrypted: bool
    entry: str
    found_password: str
    found_password_hex: str
    attempts: int
    elapsed_seconds: float
    rate_per_second: float
    workers: int
    verified: bool
    extracted: bool
    written_bytes: int
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _ZipTarget:
    archive_path: str
    entry: str
    encrypted_header: bytes
    verifier: int
    flag_bits: int
    compress_type: int


def crack_archive_password(
    archive_path: Path,
    output_dir: Path | None = None,
    *,
    wordlist: Path | None = None,
    charset: str = "digits",
    chars: str | None = None,
    min_length: int = 1,
    max_length: int | None = None,
    prefix: str = "",
    suffix: str = "",
    encoding: str = "utf-8",
    backend: str = "auto",
    workers: int = 0,
    chunk_size: int = 4096,
    max_attempts: int | None = None,
    verify: bool = True,
    sevenzip: Path | None = None,
) -> ArchiveCrackResult:
    archive_path = Path(archive_path)
    _check_file(archive_path, "压缩包")
    if backend not in {"auto", "native", "7z"}:
        raise ValueError("backend 必须是 auto/native/7z")
    if chunk_size < 1:
        raise ValueError("chunk-size 必须大于 0")
    if max_attempts is not None and max_attempts < 1:
        raise ValueError("max-attempts 必须大于 0")
    worker_count = os.cpu_count() or 1 if workers in (0, None) else workers
    worker_count = max(1, worker_count)

    started = time.perf_counter()
    selected_backend = backend
    if selected_backend == "auto":
        selected_backend = "native" if _looks_like_zip(archive_path) else "7z"
    if selected_backend == "native":
        try:
            result = _crack_zip_native(
                archive_path,
                output_dir,
                wordlist=wordlist,
                charset=charset,
                chars=chars,
                min_length=min_length,
                max_length=max_length,
                prefix=prefix,
                suffix=suffix,
                encoding=encoding,
                workers=worker_count,
                chunk_size=chunk_size,
                max_attempts=max_attempts,
                verify=verify,
                started=started,
            )
            if result.found_password or backend == "native" or not _looks_like_7z(archive_path):
                return result
        except ValueError:
            if backend == "native" or not _looks_like_7z(archive_path):
                raise
            selected_backend = "7z"
    return _crack_7z_native(
        archive_path,
        output_dir,
        wordlist=wordlist,
        charset=charset,
        chars=chars,
        min_length=min_length,
        max_length=max_length,
        prefix=prefix,
        suffix=suffix,
        encoding=encoding,
        workers=worker_count,
        chunk_size=chunk_size,
        max_attempts=max_attempts,
        sevenzip=sevenzip,
        started=started,
    )


def crack_archive_password_candidates(
    archive_path: Path,
    output_dir: Path | None,
    candidates: Iterable[bytes],
    *,
    backend: str = "auto",
    workers: int = 0,
    chunk_size: int = 4096,
    max_attempts: int | None = None,
    verify: bool = True,
    sevenzip: Path | None = None,
    encoding: str = "utf-8",
    operation: str = "archive.crack.candidates",
) -> ArchiveCrackResult:
    archive_path = Path(archive_path)
    _check_file(archive_path, "压缩包")
    if backend not in {"auto", "native", "7z"}:
        raise ValueError("backend 必须是 auto/native/7z")
    if chunk_size < 1:
        raise ValueError("chunk-size 必须大于 0")
    if max_attempts is not None and max_attempts < 1:
        raise ValueError("max-attempts 必须大于 0")
    worker_count = os.cpu_count() or 1 if workers in (0, None) else workers
    worker_count = max(1, worker_count)
    started = time.perf_counter()
    selected_backend = backend
    if selected_backend == "auto":
        selected_backend = "native" if _looks_like_zip(archive_path) else "7z"
    chunks = _chunk_candidates(candidates, chunk_size=chunk_size, max_attempts=max_attempts)
    if selected_backend == "native":
        try:
            return _crack_zip_native_candidate_chunks(
                archive_path,
                output_dir,
                chunks=chunks,
                workers=worker_count,
                verify=verify,
                started=started,
                encoding=encoding,
                operation=operation,
            )
        except ValueError:
            if backend == "native" or not _looks_like_7z(archive_path):
                raise
            selected_backend = "7z"
            chunks = _chunk_candidates(candidates, chunk_size=chunk_size, max_attempts=max_attempts)
    return _crack_native_7z_candidate_chunks(
        archive_path,
        output_dir,
        chunks=chunks,
        workers=worker_count,
        sevenzip=sevenzip,
        started=started,
        encoding=encoding,
        operation=operation,
    )


def _crack_zip_native(
    archive_path: Path,
    output_dir: Path | None,
    *,
    wordlist: Path | None,
    charset: str,
    chars: str | None,
    min_length: int,
    max_length: int | None,
    prefix: str,
    suffix: str,
    encoding: str,
    workers: int,
    chunk_size: int,
    max_attempts: int | None,
    verify: bool,
    started: float,
) -> ArchiveCrackResult:
    target = _read_zipcrypto_target(archive_path)
    found, attempts = _run_parallel_search(
        _candidate_chunks(
            wordlist=wordlist,
            charset=charset,
            chars=chars,
            min_length=min_length,
            max_length=max_length,
            prefix=prefix,
            suffix=suffix,
            encoding=encoding,
            chunk_size=chunk_size,
            max_attempts=max_attempts,
        ),
        workers,
        _native_worker,
        (target, verify),
    )
    extracted, output_paths, written = False, [], 0
    if found and output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(output_dir, pwd=found)
        extracted = True
        output_paths = [str(path) for path in sorted(output_dir.rglob("*")) if path.is_file()]
        written = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
    elapsed = max(time.perf_counter() - started, 0.000001)
    return ArchiveCrackResult(
        operation="zip.crack",
        input_path=str(archive_path),
        output_path=str(output_dir) if output_dir is not None else "-",
        output_paths=output_paths,
        backend="native-zipcrypto",
        archive_format="zip",
        encrypted=True,
        entry=target.entry,
        found_password=_decode_password(found, encoding) if found else "",
        found_password_hex=found.hex() if found else "",
        attempts=attempts,
        elapsed_seconds=round(elapsed, 6),
        rate_per_second=round(attempts / elapsed, 2),
        workers=workers,
        verified=bool(found and verify),
        extracted=extracted,
        written_bytes=written,
    )


def _crack_7z_native(
    archive_path: Path,
    output_dir: Path | None,
    *,
    wordlist: Path | None,
    charset: str,
    chars: str | None,
    min_length: int,
    max_length: int | None,
    prefix: str,
    suffix: str,
    encoding: str,
    workers: int,
    chunk_size: int,
    max_attempts: int | None,
    sevenzip: Path | None,
    started: float,
) -> ArchiveCrackResult:
    _ = sevenzip
    _check_7z_archive(archive_path)
    found, attempts = _run_parallel_search(
        _candidate_chunks(
            wordlist=wordlist,
            charset=charset,
            chars=chars,
            min_length=min_length,
            max_length=max_length,
            prefix=prefix,
            suffix=suffix,
            encoding=encoding,
            chunk_size=chunk_size,
            max_attempts=max_attempts,
        ),
        workers,
        _native_7z_worker,
        (str(archive_path), encoding),
    )
    extracted, output_paths, written = False, [], 0
    if found and output_dir is not None:
        password = _decode_password(found, encoding)
        extracted_paths = _extract_7z_archive_native(archive_path, output_dir, password=password)
        extracted = True
        output_paths = [str(path) for path in sorted(extracted_paths)]
        written = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
    elapsed = max(time.perf_counter() - started, 0.000001)
    return ArchiveCrackResult(
        operation="archive.crack",
        input_path=str(archive_path),
        output_path=str(output_dir) if output_dir is not None else "-",
        output_paths=output_paths,
        backend="native-7z",
        archive_format="7z",
        encrypted=True,
        entry="-",
        found_password=_decode_password(found, encoding) if found else "",
        found_password_hex=found.hex() if found else "",
        attempts=attempts,
        elapsed_seconds=round(elapsed, 6),
        rate_per_second=round(attempts / elapsed, 2),
        workers=workers,
        verified=bool(found),
        extracted=extracted,
        written_bytes=written,
    )


def _crack_zip_native_candidate_chunks(
    archive_path: Path,
    output_dir: Path | None,
    *,
    chunks: Iterable[list[bytes]],
    workers: int,
    verify: bool,
    started: float,
    encoding: str,
    operation: str,
) -> ArchiveCrackResult:
    target = _read_zipcrypto_target(archive_path)
    found, attempts = _run_parallel_search(chunks, workers, _native_worker, (target, verify))
    extracted, output_paths, written = False, [], 0
    if found and output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(output_dir, pwd=found)
        extracted = True
        output_paths = [str(path) for path in sorted(output_dir.rglob("*")) if path.is_file()]
        written = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
    elapsed = max(time.perf_counter() - started, 0.000001)
    return ArchiveCrackResult(
        operation=operation,
        input_path=str(archive_path),
        output_path=str(output_dir) if output_dir is not None else "-",
        output_paths=output_paths,
        backend="native-zipcrypto",
        archive_format="zip",
        encrypted=True,
        entry=target.entry,
        found_password=_decode_password(found, encoding) if found else "",
        found_password_hex=found.hex() if found else "",
        attempts=attempts,
        elapsed_seconds=round(elapsed, 6),
        rate_per_second=round(attempts / elapsed, 2),
        workers=workers,
        verified=bool(found and verify),
        extracted=extracted,
        written_bytes=written,
    )


def _crack_native_7z_candidate_chunks(
    archive_path: Path,
    output_dir: Path | None,
    *,
    chunks: Iterable[list[bytes]],
    workers: int,
    sevenzip: Path | None,
    started: float,
    encoding: str,
    operation: str,
) -> ArchiveCrackResult:
    _ = sevenzip
    _check_7z_archive(archive_path)
    found, attempts = _run_parallel_search(
        chunks, workers, _native_7z_worker, (str(archive_path), encoding)
    )
    extracted, output_paths, written = False, [], 0
    if found and output_dir is not None:
        password = _decode_password(found, encoding)
        extracted_paths = _extract_7z_archive_native(archive_path, output_dir, password=password)
        extracted = True
        output_paths = [str(path) for path in sorted(extracted_paths)]
        written = sum(path.stat().st_size for path in output_dir.rglob("*") if path.is_file())
    elapsed = max(time.perf_counter() - started, 0.000001)
    return ArchiveCrackResult(
        operation=operation,
        input_path=str(archive_path),
        output_path=str(output_dir) if output_dir is not None else "-",
        output_paths=output_paths,
        backend="native-7z",
        archive_format="7z",
        encrypted=True,
        entry="-",
        found_password=_decode_password(found, encoding) if found else "",
        found_password_hex=found.hex() if found else "",
        attempts=attempts,
        elapsed_seconds=round(elapsed, 6),
        rate_per_second=round(attempts / elapsed, 2),
        workers=workers,
        verified=bool(found),
        extracted=extracted,
        written_bytes=written,
    )


def _run_parallel_search(
    chunks: Iterable[list[bytes]],
    workers: int,
    worker_func,
    worker_args: tuple[object, ...],
) -> tuple[bytes | None, int]:
    attempts = 0
    if workers == 1:
        for chunk in chunks:
            found, used = worker_func(chunk, *worker_args)
            attempts += used
            if found is not None:
                return found, attempts
        return None, attempts
    with ProcessPoolExecutor(max_workers=workers) as pool:
        iterator = iter(chunks)
        pending = set()
        exhausted = False
        for _ in range(workers * 2):
            try:
                pending.add(pool.submit(worker_func, next(iterator), *worker_args))
            except StopIteration:
                exhausted = True
                break
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                found, used = future.result()
                attempts += used
                if found is not None:
                    for other in pending:
                        other.cancel()
                    pool.shutdown(wait=False, cancel_futures=True)
                    return found, attempts
                if not exhausted:
                    try:
                        pending.add(pool.submit(worker_func, next(iterator), *worker_args))
                    except StopIteration:
                        exhausted = True
        return None, attempts


def _native_worker(
    candidates: list[bytes], target: _ZipTarget, verify: bool
) -> tuple[bytes | None, int]:
    for index, password in enumerate(candidates, 1):
        if _zipcrypto_header_matches(password, target.encrypted_header, target.verifier) and (
            not verify or _verify_zip_password(target.archive_path, target.entry, password)
        ):
            return password, index
    return None, len(candidates)


def _native_7z_worker(
    candidates: list[bytes], archive_path: str, encoding: str
) -> tuple[bytes | None, int]:
    for index, password in enumerate(candidates, 1):
        text = _decode_password(password, encoding)
        if _verify_7z_password(Path(archive_path), text):
            return password, index
    return None, len(candidates)


def _chunk_candidates(
    candidates: Iterable[bytes], *, chunk_size: int, max_attempts: int | None
) -> Iterator[list[bytes]]:
    chunk: list[bytes] = []
    for emitted, candidate in enumerate(candidates, 1):
        chunk.append(candidate)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
        if max_attempts is not None and emitted >= max_attempts:
            break
    if chunk:
        yield chunk


def _candidate_chunks(
    *,
    wordlist: Path | None,
    charset: str,
    chars: str | None,
    min_length: int,
    max_length: int | None,
    prefix: str,
    suffix: str,
    encoding: str,
    chunk_size: int,
    max_attempts: int | None,
) -> Iterator[list[bytes]]:
    source = (
        _wordlist_candidates(wordlist)
        if wordlist is not None
        else _bruteforce_candidates(
            charset=charset,
            chars=chars,
            min_length=min_length,
            max_length=max_length,
            prefix=prefix,
            suffix=suffix,
            encoding=encoding,
        )
    )
    chunk: list[bytes] = []
    for emitted, candidate in enumerate(source, 1):
        chunk.append(candidate)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
        if max_attempts is not None and emitted >= max_attempts:
            break
    if chunk:
        yield chunk


def _wordlist_candidates(wordlist: Path) -> Iterator[bytes]:
    _check_file(wordlist, "密码字典")
    with Path(wordlist).open("rb") as handle:
        for line in handle:
            candidate = line.rstrip(b"\r\n")
            if candidate:
                yield candidate


def _bruteforce_candidates(
    *,
    charset: str,
    chars: str | None,
    min_length: int,
    max_length: int | None,
    prefix: str,
    suffix: str,
    encoding: str,
) -> Iterator[bytes]:
    if max_length is None:
        raise ValueError("未提供 --wordlist 时必须提供 --max-length")
    if min_length < 0 or max_length < min_length:
        raise ValueError("长度范围无效")
    alphabet = _resolve_bytes_charset(charset, chars, encoding)
    prefix_b = prefix.encode(encoding)
    suffix_b = suffix.encode(encoding)
    for length in range(min_length, max_length + 1):
        middle_len = length - len(prefix_b) - len(suffix_b)
        if middle_len < 0:
            continue
        for item in itertools.product(alphabet, repeat=middle_len):
            yield prefix_b + bytes(item) + suffix_b


def _resolve_bytes_charset(charset: str, chars: str | None, encoding: str) -> bytes:
    if chars is not None:
        data = chars.encode(encoding)
        if not data:
            raise ValueError("--chars 不能为空")
        return bytes(dict.fromkeys(data))
    if charset not in BYTE_ALPHABETS:
        raise ValueError(f"charset 必须是 {', '.join(sorted(BYTE_ALPHABETS))} 或提供 --chars")
    return BYTE_ALPHABETS[charset]


def _read_zipcrypto_target(archive_path: Path) -> _ZipTarget:
    if not _looks_like_zip(archive_path):
        raise ValueError("native 后端只支持 ZIP")
    with zipfile.ZipFile(archive_path) as archive:
        encrypted = [
            info for info in archive.infolist() if info.flag_bits & 0x01 and not info.is_dir()
        ]
        if not encrypted:
            raise ValueError("ZIP 没有加密条目")
        info = encrypted[0]
        if info.compress_type == 99:
            raise ValueError("检测到 WinZip AES，原生 ZipCrypto 后端不支持")
        verifier = (
            ((info._raw_time >> 8) & 0xFF) if info.flag_bits & 0x08 else ((info.CRC >> 24) & 0xFF)
        )
        with archive_path.open("rb") as handle:
            handle.seek(info.header_offset)
            header = handle.read(30)
            if len(header) != 30 or header[:4] != b"PK\x03\x04":
                raise ValueError("ZIP 本地文件头异常")
            name_len = int.from_bytes(header[26:28], "little")
            extra_len = int.from_bytes(header[28:30], "little")
            handle.seek(name_len + extra_len, os.SEEK_CUR)
            encrypted_header = handle.read(12)
        if len(encrypted_header) != 12:
            raise ValueError("ZIP 加密头不完整")
        return _ZipTarget(
            str(archive_path),
            info.filename,
            encrypted_header,
            verifier,
            info.flag_bits,
            info.compress_type,
        )


def _zipcrypto_header_matches(password: bytes, encrypted_header: bytes, verifier: int) -> bool:
    keys = _zipcrypto_init(password)
    plain = bytearray()
    for value in encrypted_header:
        key = _zipcrypto_decrypt_byte(keys)
        decrypted = value ^ key
        _zipcrypto_update(keys, decrypted)
        plain.append(decrypted)
    return plain[-1] == verifier


def _verify_zip_password(archive_path: str, entry: str, password: bytes) -> bool:
    try:
        with zipfile.ZipFile(archive_path) as archive, archive.open(entry, pwd=password) as handle:
            while handle.read(1024 * 1024):
                pass
        return True
    except (RuntimeError, OSError, zipfile.BadZipFile, zlib.error):
        return False


def _verify_7z_password(archive_path: Path, password: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="omm-7z-test-") as directory:
        try:
            _extract_7z_archive_native(archive_path, Path(directory), password=password)
            return True
        except ValueError:
            return False


def _extract_7z_archive_native(
    archive_path: Path, output_dir: Path, *, password: str | None
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    before = {path.resolve() for path in output_dir.rglob("*") if path.is_file()}
    try:
        with py7zr.SevenZipFile(archive_path, mode="r", password=password) as archive:
            for name in archive.getnames():
                _safe_join(output_dir, name.replace("\\", "/"))
            archive.extractall(path=output_dir)
    except py7zr_exceptions.PasswordRequired as error:
        raise ValueError("7z 解压失败，需要密码") from error
    except (
        py7zr_exceptions.ArchiveError,
        py7zr_exceptions.DecompressionError,
        py7zr_exceptions.UnsupportedCompressionMethodError,
        lzma.LZMAError,
        OSError,
    ) as error:
        raise ValueError(f"7z 原生解压失败：{error}") from error
    after = [path for path in output_dir.rglob("*") if path.is_file()]
    for path in after:
        _safe_join(output_dir, str(path.relative_to(output_dir)))
    return [path for path in after if path.resolve() not in before]


def _safe_join(root: Path, name: str) -> Path:
    target = (root / name).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"压缩包条目路径越界：{name}")
    return target


def _zipcrypto_init(password: bytes) -> list[int]:
    keys = [0x12345678, 0x23456789, 0x34567890]
    for value in password:
        _zipcrypto_update(keys, value)
    return keys


def _zipcrypto_update(keys: list[int], value: int) -> None:
    keys[0] = _crc32_byte(keys[0], value)
    keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
    keys[1] = (keys[1] * 134775813 + 1) & 0xFFFFFFFF
    keys[2] = _crc32_byte(keys[2], keys[1] >> 24)


def _crc32_byte(crc: int, value: int) -> int:
    return ((crc >> 8) ^ _ZIPCRC_TABLE[(crc ^ value) & 0xFF]) & 0xFFFFFFFF


def _zipcrypto_decrypt_byte(keys: list[int]) -> int:
    temp = (keys[2] | 2) & 0xFFFFFFFF
    return ((temp * (temp ^ 1)) >> 8) & 0xFF


def zipcrypto_encrypt_for_test(password: bytes, plaintext: bytes, verifier: int) -> bytes:
    keys = _zipcrypto_init(password)
    header = bytes(range(11)) + bytes([verifier & 0xFF])
    out = bytearray()
    for plain in header + plaintext:
        key = _zipcrypto_decrypt_byte(keys)
        out.append(plain ^ key)
        _zipcrypto_update(keys, plain)
    return bytes(out)


def _looks_like_zip(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(4) == b"PK\x03\x04"


def _looks_like_7z(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(6) == b"7z\xbc\xaf'\x1c"


def _check_7z_archive(path: Path) -> None:
    if not _looks_like_7z(path):
        raise ValueError("原生 7z 后端只支持 7z 文件")


def _decode_password(password: bytes, encoding: str) -> str:
    return password.decode(encoding, errors="replace")


def _check_file(path: Path, label: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
