from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

IMAGE_STEGANOGRAPHY_SALT = bytes([0, 0, 1, 2, 3, 4, 5, 6, 241, 240, 238, 33, 34, 69])
IMAGE_STEGANOGRAPHY_ITERATIONS = 1000
IMAGE_STEGANOGRAPHY_KEY_BYTES = 32
IMAGE_STEGANOGRAPHY_IV_BYTES = 16
SUPPORTED_MODES = ("enlarge", "difference")


@dataclass(frozen=True)
class ImageSteganographyResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    mode: str
    width: int
    height: int
    capacity_bytes: int
    payload_bytes: int = 0
    embedded_bytes: int = 0
    written_bytes: int = 0
    encrypted: bool = False
    password_used: bool = False
    reference_path: str | None = None
    marker_found: bool = False
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def hide_image_steganography(
    input_path: Path,
    output_path: Path,
    *,
    text: str | None = None,
    payload_path: Path | None = None,
    password: str | None = None,
    mode: str = "enlarge",
) -> ImageSteganographyResult:
    """Embed bytes using Image Steganography 1.4.5.2's native algorithms."""

    if (text is None) == (payload_path is None):
        raise ValueError("--text 与 --payload 必须且只能提供一个")
    mode = _normalise_mode(mode)
    if text is not None:
        # The VB.NET program uses Encoding.ASCII.GetBytes for text mode.
        payload = text.encode("ascii", errors="replace")
    else:
        if payload_path is None or not payload_path.is_file():
            raise FileNotFoundError(f"载荷不存在：{payload_path}")
        payload = payload_path.read_bytes()
    embedded = aes_crypt_image_steganography(password, payload, encrypt=True) if password else payload
    cover = _load_rgb_image(input_path)
    capacity = image_steganography_capacity(cover, mode=mode)
    if len(embedded) > capacity:
        raise ValueError(f"宿主容量不足：需要 {len(embedded)} bytes，可用 {capacity} bytes")
    if mode == "difference":
        stego = encode_difference_payload(embedded, cover)
        marker_found = False
    else:
        stego = encode_enlarge_payload(embedded, cover)
        marker_found = True
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stego.save(output_path)
    return ImageSteganographyResult(
        operation="image.image-steganography.hide",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode=mode,
        width=stego.width,
        height=stego.height,
        capacity_bytes=capacity,
        payload_bytes=len(payload),
        embedded_bytes=len(embedded),
        encrypted=password is not None,
        password_used=password is not None,
        marker_found=marker_found,
    )


def extract_image_steganography(
    input_path: Path,
    output_path: Path,
    *,
    password: str | None = None,
    mode: str = "auto",
    reference_path: Path | None = None,
) -> ImageSteganographyResult:
    """Extract bytes from an Image Steganography 1.4.5.2 carrier."""

    actual_mode = _normalise_mode(mode, allow_auto=True)
    stego = _load_rgb_image(input_path)
    marker_found = False
    if actual_mode == "auto":
        actual_mode = "difference" if reference_path is not None else "enlarge"
    if actual_mode == "difference":
        if reference_path is None:
            raise ValueError("difference 模式提取需要 --reference 原图")
        reference = _load_rgb_image(reference_path)
        raw = decode_difference_payload(reference, stego, auto_trim=True)
        capacity = image_steganography_capacity(reference, mode="difference")
    else:
        raw, marker_found = decode_enlarge_payload(stego, return_marker=True)
        capacity = image_steganography_capacity(stego, mode="enlarge-stego")
    payload = aes_crypt_image_steganography(password, raw, encrypt=False) if password else raw
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return ImageSteganographyResult(
        operation="image.image-steganography.extract",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        mode=actual_mode,
        width=stego.width,
        height=stego.height,
        capacity_bytes=capacity,
        payload_bytes=len(payload),
        embedded_bytes=len(raw),
        written_bytes=len(payload),
        encrypted=password is not None,
        password_used=password is not None,
        reference_path=str(reference_path) if reference_path is not None else None,
        marker_found=marker_found,
    )


def inspect_image_steganography(
    input_path: Path,
    *,
    mode: str = "auto",
    reference_path: Path | None = None,
) -> ImageSteganographyResult:
    """Report mode/capacity and attempt a non-writing marker scan."""

    actual_mode = _normalise_mode(mode, allow_auto=True)
    image = _load_rgb_image(input_path)
    marker_found = False
    embedded_bytes = 0
    if actual_mode == "auto":
        actual_mode = "difference" if reference_path is not None else "enlarge"
    if actual_mode == "difference":
        if reference_path is None:
            raise ValueError("difference 模式检查需要 --reference 原图")
        reference = _load_rgb_image(reference_path)
        raw = decode_difference_payload(reference, image, auto_trim=True)
        capacity = image_steganography_capacity(reference, mode="difference")
        embedded_bytes = len(raw)
    else:
        capacity = image_steganography_capacity(image, mode="enlarge-stego")
        try:
            raw, marker_found = decode_enlarge_payload(image, return_marker=True)
            embedded_bytes = len(raw)
        except ValueError:
            marker_found = False
            embedded_bytes = 0
    return ImageSteganographyResult(
        operation="image.image-steganography.inspect",
        input_path=str(input_path),
        output_path="",
        output_paths=[],
        mode=actual_mode,
        width=image.width,
        height=image.height,
        capacity_bytes=capacity,
        embedded_bytes=embedded_bytes,
        reference_path=str(reference_path) if reference_path is not None else None,
        marker_found=marker_found,
    )


def image_steganography_capacity(image: Image.Image, *, mode: str = "enlarge") -> int:
    """Return the original program's payload capacity in bytes."""

    if mode == "difference":
        return image.width * image.height
    if mode == "enlarge":
        return image.width * image.height * 3 - 1
    if mode == "enlarge-stego":
        if image.width % 2 or image.height % 2:
            return 0
        return (image.width // 2) * (image.height // 2) * 3 - 1
    raise ValueError(f"未知模式：{mode}")


def encode_difference_payload(payload: bytes, image: Image.Image) -> Image.Image:
    """Same-size Difference encoder: one byte is stored as R/B channel deltas."""

    source = image.convert("RGB")
    capacity = source.width * source.height
    if len(payload) > capacity:
        raise ValueError(f"宿主容量不足：需要 {len(payload)} bytes，可用 {capacity} bytes")
    output = source.copy()
    pixels = output.load()
    index = 0
    for y in range(source.height):
        for x in range(source.width):
            if index >= len(payload):
                return output
            pixels[x, y] = _gen_colour(payload[index], pixels[x, y])
            index += 1
    return output


def decode_difference_payload(
    reference: Image.Image,
    stego: Image.Image,
    *,
    auto_trim: bool = True,
) -> bytes:
    """Extract Difference-mode bytes by comparing the original and encoded images."""

    ref = reference.convert("RGB")
    enc = stego.convert("RGB")
    if ref.size != enc.size:
        raise ValueError("difference 模式的原图和隐写图尺寸不一致")
    out = bytearray(ref.width * ref.height + 1)
    last_changed = 0
    index = 0
    ref_px = ref.load()
    enc_px = enc.load()
    for y in range(ref.height):
        for x in range(ref.width):
            if ref_px[x, y] != enc_px[x, y]:
                out[index] = _get_data(ref_px[x, y], enc_px[x, y])
                last_changed = index
            else:
                out[index] = 0
            index += 1
    if auto_trim:
        return bytes(out[: last_changed + 1])
    return bytes(out[: ref.width * ref.height])


def encode_enlarge_payload(payload: bytes, image: Image.Image) -> Image.Image:
    """Double-size Enlarge encoder: a 2x2 block stores up to three difference bytes."""

    source = image.convert("RGB")
    capacity = source.width * source.height * 3 - 1
    if len(payload) > capacity:
        raise ValueError(f"宿主容量不足：需要 {len(payload)} bytes，可用 {capacity} bytes")
    data = bytes(payload) + b"\x01"
    plane_capacity = source.width * source.height
    chunks = [data[i : i + plane_capacity] for i in range(0, len(data), plane_capacity)]
    while len(chunks) < 3:
        chunks.append(b"")
    diff_planes = [
        encode_difference_payload(chunk, source) if chunk else source for chunk in chunks[:3]
    ]
    output = Image.new("RGB", (source.width * 2, source.height * 2))
    out_px = output.load()
    src_px = source.load()
    p1 = diff_planes[0].load()
    p2 = diff_planes[1].load()
    p3 = diff_planes[2].load()
    for y in range(source.height):
        oy = y * 2
        for x in range(source.width):
            ox = x * 2
            out_px[ox, oy] = src_px[x, y]
            out_px[ox + 1, oy] = p1[x, y]
            out_px[ox + 1, oy + 1] = p2[x, y]
            out_px[ox, oy + 1] = p3[x, y]
    return output


def decode_enlarge_payload(
    stego: Image.Image,
    *,
    return_marker: bool = False,
) -> bytes | tuple[bytes, bool]:
    """Extract Enlarge-mode data from a doubled image and remove the 0x01 marker."""

    image = stego.convert("RGB")
    if image.width % 2 or image.height % 2:
        raise ValueError("enlarge 模式隐写图尺寸应为偶数")
    half_w = image.width // 2
    half_h = image.height // 2
    reference = Image.new("RGB", (half_w, half_h))
    diff1 = Image.new("RGB", (half_w, half_h))
    diff2 = Image.new("RGB", (half_w, half_h))
    diff3 = Image.new("RGB", (half_w, half_h))
    in_px = image.load()
    ref_px = reference.load()
    d1_px = diff1.load()
    d2_px = diff2.load()
    d3_px = diff3.load()
    for y in range(half_h):
        iy = y * 2
        for x in range(half_w):
            ix = x * 2
            ref_px[x, y] = in_px[ix, iy]
            d1_px[x, y] = in_px[ix + 1, iy]
            d2_px[x, y] = in_px[ix + 1, iy + 1]
            d3_px[x, y] = in_px[ix, iy + 1]
    chunks = [
        decode_difference_payload(reference, diff1, auto_trim=False),
        decode_difference_payload(reference, diff2, auto_trim=False),
        decode_difference_payload(reference, diff3, auto_trim=False),
    ]
    combined = b"".join(chunks) + b"\x00"
    marker_index = combined.rfind(b"\x01")
    marker_found = marker_index >= 0
    payload = combined[:marker_index] if marker_found else b"\x00"
    if return_marker:
        return payload, marker_found
    return payload


def aes_crypt_image_steganography(password: str | None, data: bytes, *, encrypt: bool) -> bytes:
    """AES-CBC/PKCS7 helper matching the VB.NET AESCryptByte method."""

    if password is None:
        return bytes(data)
    key_iv = _pbkdf2_key_iv(password)
    key = key_iv[:IMAGE_STEGANOGRAPHY_KEY_BYTES]
    iv = key_iv[IMAGE_STEGANOGRAPHY_KEY_BYTES:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    if encrypt:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()
    decryptor = cipher.decryptor()
    try:
        padded = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as error:
        raise ValueError("Image Steganography AES 解密失败，密码可能错误") from error


def _pbkdf2_key_iv(password: str) -> bytes:
    derive = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=IMAGE_STEGANOGRAPHY_KEY_BYTES + IMAGE_STEGANOGRAPHY_IV_BYTES,
        salt=IMAGE_STEGANOGRAPHY_SALT,
        iterations=IMAGE_STEGANOGRAPHY_ITERATIONS,
    )
    return derive.derive(password.encode("utf-8"))


def _load_rgb_image(path: Path) -> Image.Image:
    if not path.is_file():
        raise FileNotFoundError(f"图片不存在：{path}")
    with Image.open(path) as source:
        return source.convert("RGB")


def _normalise_mode(mode: str, *, allow_auto: bool = False) -> str:
    value = mode.lower().replace("_", "-")
    aliases = {
        "diff": "difference",
        "difference": "difference",
        "enlarge": "enlarge",
        "large": "enlarge",
    }
    if allow_auto:
        aliases["auto"] = "auto"
    if value not in aliases:
        choices = ", ".join(["auto"] + list(SUPPORTED_MODES)) if allow_auto else ", ".join(SUPPORTED_MODES)
        raise ValueError(f"未知 Image Steganography 模式：{mode}；可选 {choices}")
    return aliases[value]


def _gen_colour(value: int, colour: tuple[int, int, int]) -> tuple[int, int, int]:
    r, g, b = colour
    low = value % 16
    high = (value - low) // 16
    new_r = r + low if r < 128 else r - low
    new_b = round(b + high) if b < 128 else round(b - high)
    return int(new_r), int(g), int(new_b)


def _get_data(colour1: tuple[int, int, int], colour2: tuple[int, int, int]) -> int:
    value = abs(colour1[0] - colour2[0]) + abs(colour1[2] - colour2[2]) * 16
    if value > 255:
        raise ValueError(f"difference 像素差超出 Image Steganography 字节范围：{value}")
    return value
