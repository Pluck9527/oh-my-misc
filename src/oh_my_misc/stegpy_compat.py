from __future__ import annotations

import base64
import os
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

MAGIC_NUMBER = b"stegv3"
FERNET_TOKEN_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
)
SUPPORTED_IMAGE_FORMATS = {".png", ".bmp", ".gif", ".webp"}


@dataclass(frozen=True)
class StegpyResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    host_format: str
    bits: int
    capacity_bytes: int
    payload_bytes: int = 0
    embedded_bytes: int = 0
    written_bytes: int = 0
    payload_filename: str | None = None
    encrypted: bool = False
    found_password: str | None = None
    attempts: int = 0
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def hide_stegpy(
    host_path: Path,
    output_path: Path,
    *,
    text: str | None = None,
    payload_path: Path | None = None,
    password: str | None = None,
    bits: int = 2,
) -> StegpyResult:
    if (text is None) == (payload_path is None):
        raise ValueError("--text 与 --payload 必须且只能提供一个")
    _check_bits(bits)
    payload_filename: str | None = None
    if payload_path is not None:
        if not payload_path.is_file():
            raise FileNotFoundError(f"载荷不存在：{payload_path}")
        payload = payload_path.read_bytes()
        payload_filename = payload_path.name
    else:
        payload = (text or "").encode("utf-8")
    formatted = _format_message(payload, filename=payload_filename)
    embedded = _encrypt_info(password, formatted) if password else formatted
    carrier, host_format, saver = _load_host_carrier(host_path)
    capacity = _carrier_capacity(carrier, bits)
    if len(embedded) > capacity:
        raise ValueError(f"宿主容量不足：需要 {len(embedded)} bytes，可用 {capacity} bytes")
    encoded = _encode_message(carrier, embedded, bits)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    saver(encoded, output_path)
    return StegpyResult(
        operation="image.stegpy.hide",
        input_path=str(host_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        host_format=host_format,
        bits=bits,
        capacity_bytes=capacity,
        payload_bytes=len(payload),
        embedded_bytes=len(embedded),
        payload_filename=payload_filename,
        encrypted=password is not None,
        found_password=password,
    )


def extract_stegpy(
    host_path: Path,
    output_path: Path,
    *,
    password: str | None = None,
) -> StegpyResult:
    carrier, host_format, _ = _load_host_carrier(host_path)
    decoded, bits = _decode_message(carrier)
    decrypted = _decrypt_embedded_info(password, decoded) if password else bytes(decoded)
    payload, payload_filename = _parse_formatted_message(decrypted)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return StegpyResult(
        operation="image.stegpy.extract",
        input_path=str(host_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        host_format=host_format,
        bits=bits,
        capacity_bytes=_carrier_capacity(carrier, bits),
        written_bytes=len(payload),
        payload_filename=payload_filename,
        encrypted=password is not None,
        found_password=password,
    )


def brute_stegpy(
    host_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    contains: bytes | None = None,
    prefix: bytes | None = None,
) -> StegpyResult:
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"字典不存在：{wordlist_path}")
    carrier, host_format, _ = _load_host_carrier(host_path)
    decoded, bits = _decode_message(carrier)
    attempts = 0
    last_error = ""
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            attempts += 1
            try:
                decrypted = _decrypt_embedded_info(candidate, decoded)
                payload, payload_filename = _parse_formatted_message(decrypted)
            except ValueError as error:
                last_error = str(error)
                continue
            if contains is not None and contains not in payload:
                continue
            if prefix is not None and not payload.startswith(prefix):
                continue
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(payload)
            return StegpyResult(
                operation="image.stegpy.brute",
                input_path=str(host_path),
                output_path=str(output_path),
                output_paths=[str(output_path)],
                host_format=host_format,
                bits=bits,
                capacity_bytes=_carrier_capacity(carrier, bits),
                written_bytes=len(payload),
                payload_filename=payload_filename,
                encrypted=True,
                found_password=candidate,
                attempts=attempts,
            )
    extra = f"；最后错误：{last_error}" if last_error else ""
    raise ValueError(f"字典爆破失败，尝试 {attempts} 个密码{extra}")


def _load_host_carrier(host_path: Path) -> tuple[np.ndarray, str, object]:
    if not host_path.is_file():
        raise FileNotFoundError(f"宿主文件不存在：{host_path}")
    suffix = host_path.suffix.lower()
    if suffix == ".wav":
        content = np.fromfile(host_path, dtype=np.uint8)
        if content.size <= 10000:
            raise ValueError("WAV 数据太短，stegpy 需要 10000 字节后作为载体")
        header = content[:10000].copy()
        data = content[10000:].copy()

        def save_wav(encoded: np.ndarray, output_path: Path) -> None:
            np.concatenate((header, encoded.reshape(-1))).astype(np.uint8).tofile(output_path)

        return data, "wav", save_wav
    if suffix in {".jpg", ".jpeg"}:
        raise ValueError("当前实现不写 JPEG DCT 系数；请用 PNG/BMP/GIF/WebP/WAV 载体")
    if suffix not in SUPPORTED_IMAGE_FORMATS:
        raise ValueError("stegpy 兼容模式支持 PNG/BMP/GIF/WebP/WAV")
    with Image.open(host_path) as source:
        image = source.convert("RGB")
    carrier = np.asarray(image, dtype=np.uint8).copy()

    def save_image(encoded: np.ndarray, output_path: Path) -> None:
        Image.fromarray(encoded.astype(np.uint8), "RGB").save(output_path)

    return carrier, suffix.lstrip("."), save_image


def _format_message(payload: bytes, *, filename: str | None = None) -> bytes:
    if filename is None:
        return MAGIC_NUMBER + len(payload).to_bytes(4, "big") + b"\x00" + payload
    encoded_name = filename.encode("utf-8")
    if len(encoded_name) > 255:
        raise ValueError("stegpy 嵌入文件名不能超过 255 字节")
    return (
        MAGIC_NUMBER
        + len(payload).to_bytes(4, "big")
        + len(encoded_name).to_bytes(1, "big")
        + encoded_name
        + payload
    )


def _parse_formatted_message(data: bytes | np.ndarray) -> tuple[bytes, str | None]:
    raw = bytes(data)
    if raw[: len(MAGIC_NUMBER)] != MAGIC_NUMBER:
        raise ValueError("未找到 stegpy 魔数，密码可能错误或载体没有 stegpy 数据")
    if len(raw) < 11:
        raise ValueError("stegpy 头部不完整")
    payload_len = int.from_bytes(raw[6:10], "big")
    filename_len = raw[10]
    filename_end = 11 + filename_len
    payload_end = filename_end + payload_len
    if payload_end > len(raw):
        raise ValueError("stegpy 载荷长度越界")
    filename = raw[11:filename_end].decode("utf-8") if filename_len else None
    return raw[filename_end:payload_end], filename


def _encode_message(carrier: np.ndarray, message: bytes, bits: int) -> np.ndarray:
    _check_bits(bits)
    shape = carrier.shape
    flat = carrier.reshape(-1).copy()
    divisor = 8 // bits
    original_size = flat.size
    if flat.size % divisor:
        flat = np.resize(flat, flat.size + (divisor - flat.size % divisor))
    msg = np.zeros(len(flat) // divisor, dtype=np.uint8)
    msg[: len(message)] = np.frombuffer(message, dtype=np.uint8)
    flat[: divisor * len(message)] &= 256 - 2**bits
    for index in range(divisor):
        flat[index::divisor] |= (msg >> (bits * index)) & (2**bits - 1)
    operand = 0 if bits == 1 else 16 if bits == 2 else 32
    flat[0] = (flat[0] & 207) | operand
    if flat.size != original_size:
        flat = np.resize(flat, original_size)
    return flat.reshape(shape)


def _decode_message(carrier: np.ndarray) -> tuple[np.ndarray, int]:
    flat = carrier.reshape(-1).copy()
    if flat.size == 0:
        raise ValueError("载体为空")
    bits = 2 ** int((int(flat[0]) & 48) >> 4)
    _check_bits(bits)
    divisor = 8 // bits
    if flat.size % divisor:
        flat = np.resize(flat, flat.size + (divisor - flat.size % divisor))
    msg = np.zeros(len(flat) // divisor, dtype=np.uint8)
    for index in range(divisor):
        msg |= (flat[index::divisor] & (2**bits - 1)) << (bits * index)
    return msg, bits


def _carrier_capacity(carrier: np.ndarray, bits: int) -> int:
    _check_bits(bits)
    return int(carrier.size * bits // 8)


def _check_bits(bits: int) -> None:
    if bits not in {1, 2, 4}:
        raise ValueError("bits 必须是 1、2 或 4")


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _encrypt_info(password: str, data: bytes) -> bytes:
    salt = os.urandom(16)
    return salt + Fernet(_derive_key(password, salt)).encrypt(data)


def _decrypt_embedded_info(password: str | None, encrypted_info: bytes | np.ndarray) -> bytes:
    if not password:
        raise ValueError("加密 stegpy 数据需要 --password 或 --wordlist")
    raw = bytes(encrypted_info)
    if len(raw) <= 16:
        raise ValueError("加密 stegpy 数据太短")
    salt = raw[:16]
    token = raw[16:]
    fernet = Fernet(_derive_key(password, salt))
    last_error: Exception | None = None
    for end in dict.fromkeys(_fernet_token_lengths(token)):
        try:
            return fernet.decrypt(token[:end])
        except InvalidToken as error:
            last_error = error
    if last_error is not None:
        raise ValueError("密码错误或 Fernet token 不完整") from last_error
    raise ValueError("未找到 Fernet token 结束位置")


def _fernet_token_lengths(token: bytes) -> list[int]:
    max_end = 0
    for byte in token:
        if byte not in FERNET_TOKEN_BYTES:
            break
        max_end += 1
    ends: list[int] = []
    padding_index = token.find(b"=")
    if padding_index != -1:
        padding_end = padding_index + 1
        while padding_end < len(token) and token[padding_end] == ord("="):
            padding_end += 1
        if padding_end <= max_end:
            ends.append(padding_end)
    ends.extend(end for end in range(4, max_end + 1) if end % 4 == 0)
    return ends
