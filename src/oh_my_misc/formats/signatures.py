from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    kind: str
    media_type: str
    extensions: tuple[str, ...]
    evidence: str


def detect_signature(header: bytes) -> Signature | None:
    checks = (
        (header.startswith(b"\x89PNG\r\n\x1a\n"), Signature("png", "image/png", (".png",), "PNG signature")),
        (header.startswith(b"\xff\xd8\xff"), Signature("jpeg", "image/jpeg", (".jpg", ".jpeg", ".jpe"), "JPEG SOI marker")),
        (header.startswith((b"GIF87a", b"GIF89a")), Signature("gif", "image/gif", (".gif",), "GIF signature")),
        (header.startswith(b"BM"), Signature("bmp", "image/bmp", (".bmp", ".dib"), "BMP signature")),
        (header.startswith((b"II*\x00", b"MM\x00*")), Signature("tiff", "image/tiff", (".tif", ".tiff"), "TIFF byte-order marker")),
        (len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP", Signature("webp", "image/webp", (".webp",), "RIFF/WEBP signature")),
        (header.startswith(b"%PDF-"), Signature("pdf", "application/pdf", (".pdf",), "PDF header")),
        (header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")), Signature("zip", "application/zip", (".zip",), "ZIP local/central marker")),
        (header.startswith(b"\x0a\x0d\x0d\x0a"), Signature("pcapng", "application/x-pcapng", (".pcapng",), "PCAPNG section header")),
        (header.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")), Signature("pcap", "application/vnd.tcpdump.pcap", (".pcap", ".cap"), "PCAP magic")),
    )
    return next((signature for matched, signature in checks if matched), None)


def dimensions(kind: str, header: bytes) -> tuple[int, int] | None:
    if kind == "png" and len(header) >= 24 and header[12:16] == b"IHDR":
        return int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")
    if kind == "gif" and len(header) >= 10:
        return int.from_bytes(header[6:8], "little"), int.from_bytes(header[8:10], "little")
    if kind == "bmp" and len(header) >= 26:
        dib_size = int.from_bytes(header[14:18], "little")
        if dib_size == 12:
            return int.from_bytes(header[18:20], "little"), int.from_bytes(header[20:22], "little")
        if dib_size >= 40:
            width = int.from_bytes(header[18:22], "little", signed=True)
            height = abs(int.from_bytes(header[22:26], "little", signed=True))
            return abs(width), height
    if kind == "jpeg":
        return _jpeg_dimensions(header)
    return None


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    offset = 2
    frame_markers = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return None
        marker = data[offset]
        offset += 1
        if marker in {0x01, *range(0xD0, 0xDA)}:
            continue
        if offset + 2 > len(data):
            return None
        segment_length = int.from_bytes(data[offset : offset + 2], "big")
        if segment_length < 2 or offset + segment_length > len(data):
            return None
        if marker in frame_markers and segment_length >= 7:
            height = int.from_bytes(data[offset + 3 : offset + 5], "big")
            width = int.from_bytes(data[offset + 5 : offset + 7], "big")
            return width, height
        offset += segment_length
    return None
