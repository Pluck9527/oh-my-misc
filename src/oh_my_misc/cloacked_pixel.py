from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
from Crypto.Cipher import AES
from PIL import Image


@dataclass(frozen=True)
class CloackedPixelResult:
    operation: str
    input_path: str
    output_path: str | None
    width: int
    height: int
    capacity_bytes: int
    payload_bytes: int = 0
    encrypted_bytes: int = 0
    written_bytes: int = 0
    block_size: int = 100
    channel_means: dict[str, float] | None = None
    suspicious_blocks: dict[str, int] | None = None
    found_password: str | None = None
    attempts: int = 0
    output_paths: list[str] | None = None
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        if payload["output_paths"] is None:
            payload["output_paths"] = [self.output_path] if self.output_path else []
        return {"status": "success", **payload}


def hide_cloacked_pixel(
    image_path: Path,
    payload_path: Path,
    output_path: Path,
    *,
    password: str,
    iv: bytes | None = None,
) -> CloackedPixelResult:
    if not image_path.is_file():
        raise FileNotFoundError(f"图片不存在：{image_path}")
    if not payload_path.is_file():
        raise FileNotFoundError(f"载荷不存在：{payload_path}")
    if not password:
        raise ValueError("cloacked-pixel hide/extract 需要密码")
    with Image.open(image_path) as source:
        image = source.convert("RGBA")
    payload = payload_path.read_bytes()
    encrypted = _encrypt_aes_cbc(payload, password, iv=iv)
    bits = _decompose_cloacked(encrypted)
    while len(bits) % 3:
        bits.append(0)
    capacity_bits = image.width * image.height * 3
    if len(bits) > capacity_bits:
        raise ValueError(f"载荷过大：需要 {len(bits)} bits，可用 {capacity_bits} bits")
    pixels = np.asarray(image).copy()
    bit_array = np.asarray(bits, dtype=np.uint8)
    flat_rgba = pixels.reshape(-1, 4)
    pixel_indexes = np.arange(len(bit_array)) // 3
    channel_indexes = np.arange(len(bit_array)) % 3
    flat_rgba[pixel_indexes, channel_indexes] = (
        flat_rgba[pixel_indexes, channel_indexes] & 0xFE
    ) | bit_array
    output_path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(pixels, "RGBA").save(output_path, "PNG")
    return CloackedPixelResult(
        operation="image.cloacked-pixel.hide",
        input_path=str(image_path),
        output_path=str(output_path),
        width=image.width,
        height=image.height,
        capacity_bytes=capacity_bits // 8,
        payload_bytes=len(payload),
        encrypted_bytes=len(encrypted),
        output_paths=[str(output_path)],
    )


def extract_cloacked_pixel(
    stego_path: Path,
    output_path: Path,
    *,
    password: str,
    keep_padding: bool = False,
) -> CloackedPixelResult:
    if not password:
        raise ValueError("cloacked-pixel hide/extract 需要密码")
    image, encrypted = _read_cloacked_encrypted(stego_path)
    payload = _decrypt_aes_cbc(encrypted, password, keep_padding=keep_padding)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return CloackedPixelResult(
        operation="image.cloacked-pixel.extract",
        input_path=str(stego_path),
        output_path=str(output_path),
        width=image.width,
        height=image.height,
        capacity_bytes=(image.width * image.height * 3) // 8,
        encrypted_bytes=len(encrypted),
        written_bytes=len(payload),
        found_password=password,
        output_paths=[str(output_path)],
    )


def brute_cloacked_pixel(
    stego_path: Path,
    wordlist_path: Path,
    output_path: Path,
    *,
    keep_padding: bool = False,
    contains: bytes | None = None,
    prefix: bytes | None = None,
) -> CloackedPixelResult:
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"字典不存在：{wordlist_path}")
    image, encrypted = _read_cloacked_encrypted(stego_path)
    attempts = 0
    last_padding_error = ""
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue
            attempts += 1
            try:
                payload = _decrypt_aes_cbc(encrypted, candidate, keep_padding=keep_padding)
            except ValueError as error:
                last_padding_error = str(error)
                continue
            if contains is not None and contains not in payload:
                continue
            if prefix is not None and not payload.startswith(prefix):
                continue
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(payload)
            return CloackedPixelResult(
                operation="image.cloacked-pixel.brute",
                input_path=str(stego_path),
                output_path=str(output_path),
                width=image.width,
                height=image.height,
                capacity_bytes=(image.width * image.height * 3) // 8,
                encrypted_bytes=len(encrypted),
                written_bytes=len(payload),
                found_password=candidate,
                attempts=attempts,
                output_paths=[str(output_path)],
            )
    extra = f"；最后错误：{last_padding_error}" if last_padding_error else ""
    raise ValueError(f"字典爆破失败，尝试 {attempts} 个密码{extra}")


def _read_cloacked_encrypted(stego_path: Path) -> tuple[Image.Image, bytes]:
    if not stego_path.is_file():
        raise FileNotFoundError(f"图片不存在：{stego_path}")
    with Image.open(stego_path) as source:
        image = source.convert("RGBA")
    pixels = np.asarray(image)
    bits = (pixels[:, :, :3].reshape(-1) & 1).astype(np.uint8).tolist()
    return image, _assemble_cloacked(bits)


def analyse_cloacked_pixel(
    image_path: Path,
    *,
    block_size: int = 100,
    threshold: float = 0.08,
) -> CloackedPixelResult:
    if not image_path.is_file():
        raise FileNotFoundError(f"图片不存在：{image_path}")
    if block_size < 1:
        raise ValueError("block_size 必须大于 0")
    if threshold < 0:
        raise ValueError("threshold 不能小于 0")
    with Image.open(image_path) as source:
        image = source.convert("RGBA")
    lsb = np.asarray(image)[:, :, :3] & 1
    names = ("r", "g", "b")
    means = {name: float(lsb[:, :, index].mean()) for index, name in enumerate(names)}
    suspicious: dict[str, int] = {}
    flat = lsb.reshape(-1, 3)
    for index, name in enumerate(names):
        blocks = [flat[start : start + block_size, index] for start in range(0, len(flat), block_size)]
        suspicious[name] = sum(1 for block in blocks if block.size and abs(float(block.mean()) - 0.5) <= threshold)
    return CloackedPixelResult(
        operation="image.cloacked-pixel.analyse",
        input_path=str(image_path),
        output_path=None,
        width=image.width,
        height=image.height,
        capacity_bytes=(image.width * image.height * 3) // 8,
        block_size=block_size,
        channel_means=means,
        suspicious_blocks=suspicious,
        output_paths=[],
        count=sum(suspicious.values()),
    )


def _decompose_cloacked(data: bytes) -> list[int]:
    stream = struct.pack("<i", len(data)) + data
    return [(byte >> bit) & 1 for byte in stream for bit in range(7, -1, -1)]


def _assemble_cloacked(bits: list[int]) -> bytes:
    if len(bits) < 32:
        raise ValueError("LSB 数据不足，缺少长度头")
    raw = bytearray()
    for index in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | int(bit)
        raw.append(value)
    payload_size = struct.unpack("<i", raw[:4])[0]
    if payload_size < 0 or payload_size > len(raw) - 4:
        raise ValueError(f"无效 cloacked-pixel 载荷长度：{payload_size}")
    return bytes(raw[4 : 4 + payload_size])


def _encrypt_aes_cbc(data: bytes, password: str, *, iv: bytes | None = None) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    resolved_iv = os.urandom(AES.block_size) if iv is None else iv
    if len(resolved_iv) != AES.block_size:
        raise ValueError(f"IV 长度必须为 {AES.block_size} bytes")
    cipher = AES.new(key, AES.MODE_CBC, resolved_iv)
    return resolved_iv + cipher.encrypt(_pad32(data))


def _decrypt_aes_cbc(data: bytes, password: str, *, keep_padding: bool) -> bytes:
    if len(data) < AES.block_size * 2 or len(data) % AES.block_size:
        raise ValueError("加密载荷长度不是有效 AES-CBC 数据")
    key = hashlib.sha256(password.encode()).digest()
    iv = data[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data[AES.block_size :])
    return decrypted if keep_padding else _unpad32(decrypted)


def _pad32(data: bytes) -> bytes:
    pad_len = 32 - (len(data) % 32)
    return data + bytes([pad_len]) * pad_len


def _unpad32(data: bytes) -> bytes:
    if not data:
        raise ValueError("解密结果为空，无法去除 padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 32 or pad_len > len(data):
        raise ValueError("无效 padding，密码可能错误")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("无效 padding，密码可能错误")
    return data[:-pad_len]
