"""PaperBack 1.10 compatible paper-backup encoder and decoder.

The implementation is a native Python port of the data format, CRC, shortened
RS(255, 223) codec, block raster and recovery-block layout in the attached GPL
PaperBack source.  It emits ordinary PNG/BMP pages and reads clean exports or
high-contrast scans without requiring the original Windows GUI.
"""

from __future__ import annotations

import bz2
import hashlib
import math
import os
import struct
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
from Crypto.Cipher import AES
from PIL import Image, ImageDraw

NDOT = 32
NDATA = 90
BLOCK_SIZE = 128
SUPERBLOCK = 0xFFFFFFFF
PBM_COMPRESSED = 0x01
PBM_ENCRYPTED = 0x02
RS_PARITY = 32
RS_PAD = 127
_FILETIME_EPOCH = 11_644_473_600
_RS_POLY = (
    0,
    249,
    59,
    66,
    4,
    43,
    126,
    251,
    97,
    30,
    3,
    213,
    50,
    66,
    170,
    5,
    24,
    5,
    170,
    66,
    50,
    213,
    3,
    30,
    97,
    251,
    126,
    43,
    4,
    66,
    59,
    249,
    0,
)


def _make_galois_tables() -> tuple[list[int], list[int]]:
    alpha = [0] * 256
    indexes = [255] * 256
    value = 1
    for exponent in range(255):
        alpha[exponent] = value
        indexes[value] = exponent
        value <<= 1
        if value & 0x100:
            value ^= 0x187
    alpha[255] = 0
    indexes[0] = 255
    return alpha, indexes


_RS_ALPHA, _RS_INDEX = _make_galois_tables()


@dataclass(frozen=True)
class BackpaperResult:
    operation: str
    input_paths: list[str]
    output_path: str
    output_paths: list[str]
    count: int
    pages: int
    filename: str
    original_bytes: int
    stored_bytes: int
    blocks: int
    corrected_bytes: int = 0
    recovered_blocks: int = 0
    compressed: bool = False
    encrypted: bool = False
    crc_valid: bool = True

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class _PageMetadata:
    datasize: int
    pagesize: int
    origsize: int
    mode: int
    attributes: int
    page: int
    filetime: int
    filecrc: int
    name_raw: bytes

    @property
    def filename(self) -> str:
        limit = 32 if self.mode & PBM_ENCRYPTED else 64
        raw = self.name_raw[:limit].split(b"\0", 1)[0]
        return raw.decode("utf-8", errors="replace") or "restored.bin"


@dataclass(frozen=True)
class _DecodedBlock:
    raw: bytes
    corrected: int

    @property
    def address(self) -> int:
        return struct.unpack_from("<I", self.raw)[0]

    @property
    def data(self) -> bytes:
        return self.raw[4:94]


def crc16(data: bytes | bytearray) -> int:
    """PaperBack's CRC-16/CCITT variant (initial value 0)."""
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode_backpaper(
    input_path: Path,
    output_path: Path,
    *,
    compress: bool = True,
    password: str | None = None,
    redundancy: int = 5,
    columns: int = 8,
    rows: int = 12,
    dot_step: int = 3,
    dot_percent: int = 70,
    border: int = 25,
) -> BackpaperResult:
    """Encode one file into PaperBack-compatible raster page images."""
    if not input_path.is_file():
        raise FileNotFoundError(f"文件不存在：{input_path}")
    if not 2 <= redundancy <= 10:
        raise ValueError("PaperBack 冗余参数必须在 2..10")
    if columns < redundancy + 1 or rows < 3:
        raise ValueError("网格过小：列数至少为 redundancy+1，行数至少为 3")
    if dot_step < 2:
        raise ValueError("点阵间距至少为 2 像素")
    if not 10 <= dot_percent <= 100:
        raise ValueError("点大小百分比必须在 10..100")

    original = input_path.read_bytes()
    if not original:
        raise ValueError("PaperBack 不接受空文件")
    packed = bz2.compress(original, compresslevel=9) if compress else original
    compressed = compress and len(packed) < len(original)
    if not compressed:
        packed = original
    aligned_size = (len(packed) + 15) & ~15
    packed_plain = packed.ljust(aligned_size, b"\0")
    file_crc = crc16(packed_plain)
    mode = PBM_COMPRESSED if compressed else 0

    name_raw = bytearray(64)
    encoded_name = input_path.name.encode("utf-8")
    name_limit = 31 if password else 64
    name_raw[: min(len(encoded_name), name_limit)] = encoded_name[:name_limit]
    stored = packed_plain
    if password:
        salt = os.urandom(16)
        iv = os.urandom(16)
        name_raw[32:64] = salt + iv
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 524_288, dklen=24)
        stored = AES.new(key, AES.MODE_CBC, iv).encrypt(packed_plain)
        mode |= PBM_ENCRYPTED

    page_size = ((columns * rows - redundancy - 2) // (redundancy + 1)) * redundancy * NDATA
    if page_size <= 0:
        raise ValueError("网格容量不足")
    page_count = math.ceil(len(stored) / page_size)
    output_paths: list[Path] = []
    filetime = _unix_to_filetime(input_path.stat().st_mtime)
    for page_index in range(page_count):
        page_offset = page_index * page_size
        page_payload = stored[page_offset : page_offset + page_size]
        page_path = _page_output_path(output_path, page_index, page_count)
        image = _render_page(
            page_payload,
            page_offset=page_offset,
            total_size=len(stored),
            original_size=len(original),
            page_size=page_size,
            page_number=page_index + 1,
            mode=mode,
            filetime=filetime,
            file_crc=file_crc,
            name_raw=bytes(name_raw),
            redundancy=redundancy,
            columns=columns,
            max_rows=rows,
            dot_step=dot_step,
            dot_percent=dot_percent,
            border=border,
        )
        page_path.parent.mkdir(parents=True, exist_ok=True)
        image.save(page_path)
        output_paths.append(page_path)

    return BackpaperResult(
        operation="image.backpaper.encode",
        input_paths=[str(input_path)],
        output_path=str(output_paths[0] if len(output_paths) == 1 else output_path.parent),
        output_paths=[str(path) for path in output_paths],
        count=len(output_paths),
        pages=len(output_paths),
        filename=input_path.name,
        original_bytes=len(original),
        stored_bytes=len(stored),
        blocks=math.ceil(len(stored) / NDATA),
        compressed=compressed,
        encrypted=bool(password),
    )


def decode_backpaper(
    image_paths: Iterable[Path],
    output_path: Path,
    *,
    password: str | None = None,
    threshold: int | None = None,
) -> BackpaperResult:
    """Decode one or more PaperBack page images and restore their file."""
    paths = list(image_paths)
    if not paths:
        raise ValueError("至少需要一张 PaperBack 页面图片")
    missing = next((path for path in paths if not path.is_file()), None)
    if missing is not None:
        raise FileNotFoundError(f"文件不存在：{missing}")

    page_blocks: list[list[_DecodedBlock]] = []
    for path in paths:
        page_blocks.append(_decode_page_image(path, threshold=threshold))
    all_blocks = [block for blocks in page_blocks for block in blocks]
    superblocks = [_parse_superblock(block.raw) for block in all_blocks if block.address == SUPERBLOCK]
    if not superblocks:
        raise ValueError("没有识别出 PaperBack 页面标签（superblock）")
    metadata = Counter(superblocks).most_common(1)[0][0]

    data_blocks: dict[int, bytes] = {}
    recovery: dict[tuple[int, int], bytes] = {}
    corrected = 0
    for block in all_blocks:
        corrected += block.corrected
        if block.address == SUPERBLOCK:
            continue
        group_size = (block.address >> 28) & 0x0F
        address = block.address & 0x0FFFFFFF
        if group_size:
            recovery[(address, group_size)] = block.data
        elif address < metadata.datasize:
            data_blocks.setdefault(address, block.data)

    recovered_blocks = 0
    for (base_address, group_size), recovery_data in recovery.items():
        addresses = [base_address + index * NDATA for index in range(group_size)]
        relevant = [address for address in addresses if address < metadata.datasize]
        missing_addresses = [address for address in relevant if address not in data_blocks]
        if len(missing_addresses) != 1:
            continue
        restored = bytearray(b"\xFF" * NDATA)
        restored[:] = _xor_bytes(restored, recovery_data)
        for address in addresses:
            if address in data_blocks:
                restored[:] = _xor_bytes(restored, data_blocks[address])
        data_blocks[missing_addresses[0]] = bytes(restored)
        recovered_blocks += 1

    expected_addresses = range(0, metadata.datasize, NDATA)
    missing_addresses = [address for address in expected_addresses if address not in data_blocks]
    if missing_addresses:
        preview = ", ".join(hex(address) for address in missing_addresses[:8])
        raise ValueError(f"仍缺少 {len(missing_addresses)} 个数据块：{preview}")
    stored = b"".join(data_blocks[address] for address in expected_addresses)[: metadata.datasize]

    packed_plain = stored
    if metadata.mode & PBM_ENCRYPTED:
        if password is None:
            raise ValueError("该 PaperBack 页面已加密，需要 --password")
        salt = metadata.name_raw[32:48]
        iv = metadata.name_raw[48:64]
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 524_288, dklen=24)
        packed_plain = AES.new(key, AES.MODE_CBC, iv).decrypt(stored)
    crc_valid = crc16(packed_plain) == metadata.filecrc
    if not crc_valid:
        message = "PaperBack 文件 CRC 校验失败"
        if metadata.mode & PBM_ENCRYPTED:
            message += "，密码可能错误"
        raise ValueError(message)

    if metadata.mode & PBM_COMPRESSED:
        try:
            restored_data = bz2.decompress(packed_plain)
        except OSError as error:
            raise ValueError("PaperBack bzip2 数据解压失败") from error
    else:
        restored_data = packed_plain[: metadata.origsize]
    if len(restored_data) != metadata.origsize:
        raise ValueError(
            f"恢复文件长度异常：期望 {metadata.origsize}，实际 {len(restored_data)}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(restored_data)
    return BackpaperResult(
        operation="image.backpaper.decode",
        input_paths=[str(path) for path in paths],
        output_path=str(output_path),
        output_paths=[str(output_path)],
        count=len(paths),
        pages=len(page_blocks),
        filename=metadata.filename,
        original_bytes=len(restored_data),
        stored_bytes=len(stored),
        blocks=len(data_blocks),
        corrected_bytes=corrected,
        recovered_blocks=recovered_blocks,
        compressed=bool(metadata.mode & PBM_COMPRESSED),
        encrypted=bool(metadata.mode & PBM_ENCRYPTED),
        crc_valid=crc_valid,
    )


def encode_paperback_block(address: int, payload: bytes) -> bytes:
    """Build one exact 128-byte PaperBack data block."""
    if not 0 <= address <= 0xFFFFFFFF:
        raise ValueError("块地址超出 uint32")
    if len(payload) > NDATA:
        raise ValueError(f"块载荷不能超过 {NDATA} 字节")
    data = bytearray(struct.pack("<I", address) + payload.ljust(NDATA, b"\0") + b"\0\0")
    struct.pack_into("<H", data, 94, crc16(data[:94]) ^ 0x55AA)
    data.extend(_rs_encode_parity(data, pad=RS_PAD))
    return bytes(data)


def decode_paperback_block(block: bytes | bytearray) -> tuple[bytes, int]:
    """Correct and validate one 128-byte PaperBack block."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"PaperBack 块必须为 {BLOCK_SIZE} 字节")
    corrected = bytearray(block)
    error_count = _rs_decode(corrected, pad=RS_PAD)
    if error_count < 0 or error_count > 16:
        raise ValueError("PaperBack Reed-Solomon 校验失败")
    expected_crc = crc16(corrected[:94]) ^ 0x55AA
    actual_crc = struct.unpack_from("<H", corrected, 94)[0]
    if expected_crc != actual_crc:
        raise ValueError("PaperBack 块 CRC 校验失败")
    return bytes(corrected), error_count


def _render_page(
    page_payload: bytes,
    *,
    page_offset: int,
    total_size: int,
    original_size: int,
    page_size: int,
    page_number: int,
    mode: int,
    filetime: int,
    file_crc: int,
    name_raw: bytes,
    redundancy: int,
    columns: int,
    max_rows: int,
    dot_step: int,
    dot_percent: int,
    border: int,
) -> Image.Image:
    pure_blocks = math.ceil(len(page_payload) / NDATA)
    string_count = math.ceil(pure_blocks / redundancy)
    total_cells = (string_count + 1) * (redundancy + 1) + 1
    rows = max(math.ceil(total_cells / columns), 3)
    if rows > max_rows:
        raise ValueError("页面数据超出配置网格容量")

    dot_size = max((dot_step * dot_percent) // 100, 1)
    cell_step = (NDOT + 3) * dot_step
    width = (columns * cell_step + dot_size + 2 * border + 3) & ~3
    height = rows * cell_step + dot_size + 2 * border
    image = Image.new("L", (width, height), 255)
    draw = ImageDraw.Draw(image)
    for column in range(columns + 1):
        x = border + column * cell_step
        draw.rectangle((x, border, x + dot_size - 1, border + rows * cell_step), fill=0)
    for row in range(rows + 1):
        y = border + row * cell_step
        draw.rectangle((border, y, border + columns * cell_step, y + dot_size - 1), fill=0)

    metadata = _build_superblock(
        datasize=total_size,
        pagesize=page_size,
        origsize=original_size,
        mode=mode,
        page=page_number,
        filetime=filetime,
        filecrc=file_crc,
        name_raw=name_raw,
    )
    blocks: dict[int, bytes] = {}
    for string_index in range(redundancy + 1):
        cell = string_index * (string_count + 1)
        if string_count + 1 >= columns:
            cell += (columns // (redundancy + 1) * string_index - cell % columns + columns) % columns
        blocks[cell] = metadata

    offset = page_offset
    for group_index in range(string_count):
        checksum = bytearray(b"\xFF" * NDATA)
        group_base = offset
        for string_index in range(redundancy):
            relative = offset - page_offset
            chunk = page_payload[relative : relative + NDATA].ljust(NDATA, b"\0")
            checksum[:] = _xor_bytes(checksum, chunk)
            block = encode_paperback_block(offset, chunk)
            cell = string_index * (string_count + 1)
            if string_count + 1 < columns:
                cell += group_index + 1
            else:
                rotation = (
                    columns // (redundancy + 1) * string_index - cell % columns + columns
                ) % columns
                cell += (group_index + 1 + rotation) % (string_count + 1)
            blocks[cell] = block
            offset += NDATA
        recovery_address = group_base ^ (redundancy << 28)
        recovery_block = encode_paperback_block(recovery_address, bytes(checksum))
        cell = redundancy * (string_count + 1)
        if string_count + 1 < columns:
            cell += group_index + 1
        else:
            rotation = (
                columns // (redundancy + 1) * redundancy - cell % columns + columns
            ) % columns
            cell += (group_index + 1 + rotation) % (string_count + 1)
        blocks[cell] = recovery_block

    for cell in range((string_count + 1) * (redundancy + 1), columns * rows):
        blocks[cell] = metadata
    for cell, block in blocks.items():
        if cell < columns * rows:
            _draw_block(image, cell, block, columns, dot_step, dot_size, border)
    return image


def _draw_block(
    image: Image.Image,
    cell: int,
    block: bytes,
    columns: int,
    dot_step: int,
    dot_size: int,
    border: int,
) -> None:
    draw = ImageDraw.Draw(image)
    cell_step = (NDOT + 3) * dot_step
    x0 = (cell % columns) * cell_step + 2 * dot_step + border
    y0 = (cell // columns) * cell_step + 2 * dot_step + border
    for row in range(NDOT):
        word = struct.unpack_from("<I", block, row * 4)[0]
        word ^= 0x55555555 if row % 2 == 0 else 0xAAAAAAAA
        for column in range(NDOT):
            if word & (1 << column):
                x = x0 + column * dot_step
                y = y0 + row * dot_step
                draw.rectangle((x, y, x + dot_size - 1, y + dot_size - 1), fill=64)


def _decode_page_image(path: Path, *, threshold: int | None) -> list[_DecodedBlock]:
    with Image.open(path) as source:
        gray = np.asarray(source.convert("L"), dtype=np.float64)
    x_lines = _find_grid_lines(gray.mean(axis=0))
    y_lines = _find_grid_lines(gray.mean(axis=1))
    if len(x_lines) < 2 or len(y_lines) < 2:
        raise ValueError(f"未能在 {path} 中定位 PaperBack 网格")
    columns = len(x_lines) - 1
    rows = len(y_lines) - 1
    blocks: list[_DecodedBlock] = []
    for row in range(rows):
        for column in range(columns):
            samples = _sample_cell(gray, x_lines, y_lines, column, row)
            decoded = _decode_sample_grid(samples, threshold=threshold)
            if decoded is not None:
                blocks.append(decoded)
    if not blocks:
        raise ValueError(f"{path} 中没有可校验的 PaperBack 数据块")
    return blocks


def _find_grid_lines(profile: np.ndarray) -> list[float]:
    darkness = 255.0 - profile
    positive = darkness[darkness > 1.0]
    if positive.size == 0:
        return []
    cutoff = max(float(np.percentile(positive, 92)) * 0.72, float(darkness.max()) * 0.48)
    indexes = np.flatnonzero(darkness >= cutoff)
    groups: list[list[int]] = []
    for index in indexes.tolist():
        if not groups or index > groups[-1][-1] + 1:
            groups.append([index])
        else:
            groups[-1].append(index)
    centers = [float(np.mean(group)) for group in groups if len(group) >= 1]
    if len(centers) < 2:
        return []
    spacings = np.diff(centers)
    likely = spacings[spacings > np.median(spacings) * 0.5]
    if likely.size:
        expected = float(np.median(likely))
        selected = [centers[0]]
        for center in centers[1:]:
            if center - selected[-1] >= expected * 0.6:
                selected.append(center)
        centers = selected
    return centers


def _sample_cell(
    gray: np.ndarray,
    x_lines: list[float],
    y_lines: list[float],
    column: int,
    row: int,
) -> np.ndarray:
    x_step = (x_lines[column + 1] - x_lines[column]) / (NDOT + 3)
    y_step = (y_lines[row + 1] - y_lines[row]) / (NDOT + 3)
    radius_x = max(round(x_step * 0.28), 0)
    radius_y = max(round(y_step * 0.28), 0)
    samples = np.empty((NDOT, NDOT), dtype=np.float64)
    for y_index in range(NDOT):
        y = round(y_lines[row] + (y_index + 2) * y_step)
        for x_index in range(NDOT):
            x = round(x_lines[column] + (x_index + 2) * x_step)
            patch = gray[
                max(0, y - radius_y) : min(gray.shape[0], y + radius_y + 1),
                max(0, x - radius_x) : min(gray.shape[1], x + radius_x + 1),
            ]
            samples[y_index, x_index] = float(patch.mean())
    return samples


def _decode_sample_grid(samples: np.ndarray, *, threshold: int | None) -> _DecodedBlock | None:
    limit = float(threshold) if threshold is not None else _two_cluster_threshold(samples)
    dark = samples < limit
    candidates = []
    for rotation in range(4):
        rotated = np.rot90(dark, rotation)
        candidates.extend((rotated, np.fliplr(rotated)))
    for candidate in candidates:
        raw = bytearray(BLOCK_SIZE)
        for row in range(NDOT):
            word = sum(int(candidate[row, column]) << column for column in range(NDOT))
            word ^= 0x55555555 if row % 2 == 0 else 0xAAAAAAAA
            struct.pack_into("<I", raw, row * 4, word)
        try:
            corrected, error_count = decode_paperback_block(raw)
        except ValueError:
            continue
        return _DecodedBlock(corrected, error_count)
    return None


def _two_cluster_threshold(values: np.ndarray) -> float:
    flattened = values.reshape(-1)
    low = float(np.percentile(flattened, 20))
    high = float(np.percentile(flattened, 80))
    for _ in range(12):
        boundary = (low + high) / 2.0
        low_values = flattened[flattened <= boundary]
        high_values = flattened[flattened > boundary]
        if not low_values.size or not high_values.size:
            break
        low = float(low_values.mean())
        high = float(high_values.mean())
    return (low + high) / 2.0


def _build_superblock(
    *,
    datasize: int,
    pagesize: int,
    origsize: int,
    mode: int,
    page: int,
    filetime: int,
    filecrc: int,
    name_raw: bytes,
) -> bytes:
    if len(name_raw) != 64:
        raise ValueError("PaperBack 文件名字段必须为 64 字节")
    header = bytearray(96)
    struct.pack_into("<IIIIBBHIIH", header, 0, SUPERBLOCK, datasize, pagesize, origsize, mode, 0x80, page, filetime & 0xFFFFFFFF, filetime >> 32, filecrc)
    header[30:94] = name_raw
    struct.pack_into("<H", header, 94, crc16(header[:94]) ^ 0x55AA)
    header.extend(_rs_encode_parity(header, pad=RS_PAD))
    return bytes(header)


def _parse_superblock(block: bytes) -> _PageMetadata:
    values = struct.unpack_from("<IIIIBBHIIH", block)
    return _PageMetadata(
        datasize=values[1],
        pagesize=values[2],
        origsize=values[3],
        mode=values[4],
        attributes=values[5],
        page=values[6],
        filetime=values[7] | (values[8] << 32),
        filecrc=values[9],
        name_raw=block[30:94],
    )


def _rs_encode_parity(data: bytes | bytearray, *, pad: int) -> bytes:
    parity = bytearray(RS_PARITY)
    for index in range(223 - pad):
        feedback = _RS_INDEX[data[index] ^ parity[0]]
        if feedback != 255:
            for parity_index in range(1, RS_PARITY):
                parity[parity_index] ^= _RS_ALPHA[
                    (feedback + _RS_POLY[RS_PARITY - parity_index]) % 255
                ]
        parity[:-1] = parity[1:]
        parity[-1] = (
            _RS_ALPHA[(feedback + _RS_POLY[0]) % 255] if feedback != 255 else 0
        )
    return bytes(parity)


def _rs_decode(data: bytearray, *, pad: int) -> int:
    syndrome = [data[0]] * RS_PARITY
    for data_index in range(1, 255 - pad):
        for index in range(RS_PARITY):
            syndrome[index] = (
                data[data_index]
                if syndrome[index] == 0
                else data[data_index]
                ^ _RS_ALPHA[(_RS_INDEX[syndrome[index]] + (112 + index) * 11) % 255]
            )
    if not any(syndrome):
        return 0
    syndrome = [_RS_INDEX[value] for value in syndrome]
    lambda_values = [0] * 33
    lambda_values[0] = 1
    b_values = [_RS_INDEX[value] for value in lambda_values]
    error_span = 0
    iteration = 0
    while iteration < 32:
        iteration += 1
        discrepancy = 0
        for index in range(iteration):
            if lambda_values[index] and syndrome[iteration - index - 1] != 255:
                discrepancy ^= _RS_ALPHA[
                    (_RS_INDEX[lambda_values[index]] + syndrome[iteration - index - 1]) % 255
                ]
        discrepancy_index = _RS_INDEX[discrepancy]
        if discrepancy_index == 255:
            b_values = [255] + b_values[:32]
            continue
        temporary = [0] * 33
        temporary[0] = lambda_values[0]
        for index in range(32):
            temporary[index + 1] = (
                lambda_values[index + 1]
                ^ _RS_ALPHA[(discrepancy_index + b_values[index]) % 255]
                if b_values[index] != 255
                else lambda_values[index + 1]
            )
        if 2 * error_span <= iteration - 1:
            error_span = iteration - error_span
            b_values = [
                255
                if value == 0
                else (_RS_INDEX[value] - discrepancy_index + 255) % 255
                for value in lambda_values
            ]
        else:
            b_values = [255] + b_values[:32]
        lambda_values = temporary

    lambda_indexes = [_RS_INDEX[value] for value in lambda_values]
    degree = max((index for index, value in enumerate(lambda_indexes) if value != 255), default=0)
    registers = [0] + lambda_indexes[1:]
    roots: list[int] = []
    locations: list[int] = []
    location = 115
    for root in range(1, 256):
        value = 1
        for index in range(degree, 0, -1):
            if registers[index] != 255:
                registers[index] = (registers[index] + index) % 255
                value ^= _RS_ALPHA[registers[index]]
        if value == 0:
            roots.append(root)
            locations.append(location)
            if len(roots) == degree:
                break
        location = (location + 116) % 255
    if len(roots) != degree:
        return -1

    omega_degree = degree - 1
    omega = [255] * max(degree, 1)
    for index in range(omega_degree + 1):
        value = 0
        for offset in range(index, -1, -1):
            if syndrome[index - offset] != 255 and lambda_indexes[offset] != 255:
                value ^= _RS_ALPHA[(syndrome[index - offset] + lambda_indexes[offset]) % 255]
        omega[index] = _RS_INDEX[value]
    for error_index in range(degree - 1, -1, -1):
        numerator = 0
        for index in range(omega_degree, -1, -1):
            if omega[index] != 255:
                numerator ^= _RS_ALPHA[(omega[index] + index * roots[error_index]) % 255]
        numerator_two = _RS_ALPHA[(roots[error_index] * 111 + 255) % 255]
        denominator = 0
        start = min(31, degree) & ~1
        for index in range(start, -1, -2):
            if lambda_indexes[index + 1] != 255:
                denominator ^= _RS_ALPHA[
                    (lambda_indexes[index + 1] + index * roots[error_index]) % 255
                ]
        location = locations[error_index]
        if numerator and location >= pad and denominator:
            data[location - pad] ^= _RS_ALPHA[
                (_RS_INDEX[numerator] + _RS_INDEX[numerator_two] + 255 - _RS_INDEX[denominator])
                % 255
            ]
    return degree


def _xor_bytes(first: bytes | bytearray, second: bytes | bytearray) -> bytes:
    return bytes(left ^ right for left, right in zip(first, second, strict=True))


def _page_output_path(output_path: Path, page_index: int, page_count: int) -> Path:
    if page_count == 1:
        return output_path
    suffix = output_path.suffix or ".png"
    return output_path.with_name(f"{output_path.stem}_{page_index + 1:04d}{suffix}")


def _unix_to_filetime(timestamp: float) -> int:
    return int((timestamp + _FILETIME_EPOCH) * 10_000_000)
