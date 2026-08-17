from __future__ import annotations

import binascii
import itertools
import json
import re
import struct
import zipfile
import zlib
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory


@dataclass(frozen=True)
class ZipPlaintextResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    tool_path: str
    mode: str
    cipher_entry: str
    plain_source: str
    offset: int | None
    keys: list[str]
    new_password: str
    decrypted: bool
    changed_password: bool
    command: list[str]
    stdout: str
    stderr: str
    written_bytes: int
    preset: str = ""
    preset_description: str = ""
    extra_plaintexts: list[str] | None = None
    generated_plaintext_hex: str = ""
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class ZipPlaintextPresetsResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    presets: list[dict[str, object]]
    count: int

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


@dataclass(frozen=True)
class PlaintextPreset:
    name: str
    aliases: tuple[str, ...]
    description: str
    default_offset: int
    plain_bytes: bytes = b""
    extra: tuple[tuple[int, bytes], ...] = ()
    requires_text: bool = False
    requires_inner_name: bool = False


@dataclass(frozen=True)
class ResolvedPlaintextPreset:
    name: str
    description: str
    plain_bytes: bytes
    offset: int
    extra: list[str]

    @property
    def plain_hex(self) -> str:
        return self.plain_bytes.hex()


_PNG_HEADER = bytes.fromhex("89504e470d0a1a0a0000000d49484452")
_EXE_DOS_STUB = bytes.fromhex(
    "0e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f7420"
    "62652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000"
)
_PCAPNG_BYTES = bytes.fromhex("00004d3c2b1a01000000ffffffffffffffff")
_XML_HEADER = b'<?xml version="1.0" encoding="UTF-8"?>'
_SVG_HEADER = b'<?xml version="1.0" '
_VMDK_HEADER = bytes.fromhex("4b444d560100000003000000")

_PRESET_LIST = (
    PlaintextPreset(
        "text",
        ("txt", "partial-text"),
        "文本/flag 片段：用 --plain-text 或 --plain-hex 给连续 8+ 字节，可用 --extra 补其它偏移片段",
        0,
        requires_text=True,
    ),
    PlaintextPreset(
        "png",
        ("png-header",),
        "PNG 文件头：89504e470d0a1a0a0000000d49484452，偏移 0",
        0,
        _PNG_HEADER,
    ),
    PlaintextPreset(
        "zip",
        ("inner-zip", "zip-local"),
        "内层 ZIP：默认已知本地文件头 PK0304@0 和内层文件名 flag.txt@30，可用 --inner-name 覆盖",
        30,
        extra=((0, b"PK\x03\x04"),),
        requires_inner_name=True,
    ),
    PlaintextPreset(
        "exe", ("dos-stub", "pe"), "EXE DOS stub 固定字符串，偏移 64", 64, _EXE_DOS_STUB
    ),
    PlaintextPreset(
        "pcapng", ("pcap",), "PCAPNG section/header 特征字节，偏移 6", 6, _PCAPNG_BYTES
    ),
    PlaintextPreset("xml", ("web.xml",), "XML 声明：<?xml version=...?>，偏移 0", 0, _XML_HEADER),
    PlaintextPreset(
        "svg", ("svg-xml",), 'SVG/XML 开头：<?xml version="1.0" ，偏移 0', 0, _SVG_HEADER
    ),
    PlaintextPreset(
        "vmdk", ("vmware",), "VMDK magic/descriptor 开头：KDMV...，偏移 0", 0, _VMDK_HEADER
    ),
    PlaintextPreset(
        "custom",
        ("raw", "manual"),
        "自定义明文：用 --plain-file/--plain-text/--plain-hex + --offset/--extra 指定任意格式",
        0,
        requires_text=True,
    ),
)

PLAINTEXT_PRESET_ALIASES = {
    alias: preset for preset in _PRESET_LIST for alias in (preset.name, *preset.aliases)
}
PLAINTEXT_PRESET_NAMES = tuple(preset.name for preset in _PRESET_LIST)


def known_plaintext_attack(
    cipher_zip: Path,
    *,
    cipher_entry: str | None = None,
    plain_file: Path | None = None,
    plain_zip: Path | None = None,
    plain_entry: str | None = None,
    output: Path | None = None,
    new_password: str | None = None,
    offset: int | None = None,
    extra: list[str] | None = None,
    truncate: int | None = None,
    keys: tuple[str, str, str] | None = None,
    decrypt: bool = False,
    keep_header: bool = False,
    ignore_check_byte: bool = False,
    jobs: int = 0,
    bkcrack: Path | None = None,
) -> ZipPlaintextResult:
    _check_file(cipher_zip, "加密 ZIP")
    _ = bkcrack
    tool = "native-python"
    entry = cipher_entry or ("-" if keys is not None else _select_encrypted_entry(cipher_zip))
    command = ["native-bkcrack", "-C", str(cipher_zip), "-c", entry]
    stdout = ""
    stderr = ""
    plain_source = "keys"
    resolved_offset = 0 if offset is None else offset

    if keys is None:
        target = _read_zip_cipher_target(cipher_zip, entry)
        if plain_zip is not None:
            _check_file(plain_zip, "已知明文 ZIP")
            plain_name = plain_entry or (plain_file.name if plain_file is not None else entry)
            plain_bytes = _read_zip_entry_payload(plain_zip, plain_name)
            plain_source = f"{plain_zip}:{plain_name}"
            command.extend(["-P", str(plain_zip), "-p", plain_name])
        else:
            if plain_file is None:
                raise ValueError("明文攻击需要 --plain-file/--plain-zip，或直接提供 --keys")
            _check_file(plain_file, "已知明文文件")
            plain_bytes = plain_file.read_bytes()
            plain_source = str(plain_file)
            command.extend(["-p", str(plain_file)])
        if truncate is not None:
            plain_bytes = plain_bytes[:truncate]
            command.extend(["-t", str(truncate)])
        if offset is not None:
            command.extend(["-o", str(offset)])
        extra_plaintext = _expand_extra_plaintext(extra or [])
        for item in extra or []:
            off, value = _parse_extra(item)
            command.extend(["-x", str(off), value])
        if ignore_check_byte:
            command.append("--ignore-check-byte")
        if jobs > 0:
            command.extend(["-j", str(jobs)])
        found_key_ints = _recover_keys_known_plaintext(
            target.ciphertext,
            None if ignore_check_byte else target.check_byte,
            plain_bytes,
            resolved_offset,
            extra_plaintext,
            jobs=jobs,
        )
        found_keys = [_format_key(part) for part in found_key_ints]
        stdout = "Keys: " + " ".join(found_keys)
    else:
        found_keys = [_normalize_key(part) for part in keys]
        command.extend(["-k", *found_keys])

    output_paths: list[str] = []
    written = 0
    changed_password = False
    decrypted_done = False
    action_command: list[str] = []
    if output is not None:
        if decrypt:
            action_command = [
                "native-bkcrack",
                "-C",
                str(cipher_zip),
                "-k",
                *found_keys,
                "-D",
                str(output),
            ]
            if keep_header:
                action_command.append("--keep-header")
            mode = "decrypt"
            decrypted_done = True
            _rewrite_archive_with_keys(
                cipher_zip,
                output,
                tuple(found_keys),
                new_password=None,
                keep_header=keep_header,
            )
        else:
            password = "" if new_password is None else new_password
            action_command = [
                "native-bkcrack",
                "-C",
                str(cipher_zip),
                "-k",
                *found_keys,
                "-U",
                str(output),
                password,
            ]
            mode = "change-password"
            changed_password = True
            _rewrite_archive_with_keys(
                cipher_zip,
                output,
                tuple(found_keys),
                new_password=password,
                keep_header=False,
            )
        output_paths = [str(output)] if output.exists() else []
        written = output.stat().st_size if output.exists() and output.is_file() else 0
    else:
        mode = "keys"

    return ZipPlaintextResult(
        operation="zip.plaintext",
        input_path=str(cipher_zip),
        output_path=str(output) if output is not None else "-",
        output_paths=output_paths,
        tool_path=tool,
        mode=mode,
        cipher_entry=entry,
        plain_source=plain_source,
        offset=offset,
        keys=found_keys,
        new_password="" if new_password is None else new_password,
        decrypted=decrypted_done,
        changed_password=changed_password,
        command=action_command or command,
        stdout=stdout[-4000:],
        stderr=stderr[-4000:],
        written_bytes=written,
    )


def list_plaintext_presets() -> ZipPlaintextPresetsResult:
    presets = []
    for preset in _PRESET_LIST:
        presets.append(
            {
                "name": preset.name,
                "aliases": list(preset.aliases),
                "description": preset.description,
                "default_offset": preset.default_offset,
                "plain_hex": preset.plain_bytes.hex(),
                "extra": [f"{offset}:{data.hex()}" for offset, data in preset.extra],
                "requires_text": preset.requires_text,
                "requires_inner_name": preset.requires_inner_name,
            }
        )
    return ZipPlaintextPresetsResult(
        operation="zip.plaintext.presets",
        input_path="-",
        output_path="-",
        output_paths=[],
        presets=presets,
        count=len(presets),
    )


def known_plaintext_preset_attack(
    cipher_zip: Path,
    preset: str,
    *,
    cipher_entry: str | None = None,
    inner_name: str | None = None,
    plain_file: Path | None = None,
    plain_text: str | None = None,
    plain_hex: str | None = None,
    preset_file: Path | None = None,
    output: Path | None = None,
    new_password: str | None = None,
    offset: int | None = None,
    extra: list[str] | None = None,
    extra_text: list[str] | None = None,
    extra_hex: list[str] | None = None,
    truncate: int | None = None,
    decrypt: bool = False,
    keep_header: bool = False,
    ignore_check_byte: bool = False,
    jobs: int = 0,
    bkcrack: Path | None = None,
    encoding: str = "utf-8",
) -> ZipPlaintextResult:
    resolved = resolve_plaintext_preset(
        preset,
        inner_name=inner_name,
        plain_file=plain_file,
        plain_text=plain_text,
        plain_hex=plain_hex,
        preset_file=preset_file,
        offset=offset,
        extra=extra,
        extra_text=extra_text,
        extra_hex=extra_hex,
        encoding=encoding,
    )
    with TemporaryDirectory(prefix="omm_plaintext_") as temp_dir:
        plain_file = Path(temp_dir) / f"{resolved.name}_plain.bin"
        plain_file.write_bytes(resolved.plain_bytes)
        result = known_plaintext_attack(
            cipher_zip,
            cipher_entry=cipher_entry,
            plain_file=plain_file,
            output=output,
            new_password=new_password,
            offset=resolved.offset,
            extra=resolved.extra,
            truncate=truncate,
            decrypt=decrypt,
            keep_header=keep_header,
            ignore_check_byte=ignore_check_byte,
            jobs=jobs,
            bkcrack=bkcrack,
        )
    return replace(
        result,
        preset=resolved.name,
        preset_description=resolved.description,
        plain_source=f"preset:{resolved.name}",
        extra_plaintexts=resolved.extra,
        generated_plaintext_hex=resolved.plain_hex,
    )


def resolve_plaintext_preset(
    preset: str,
    *,
    inner_name: str | None = None,
    plain_file: Path | None = None,
    plain_text: str | None = None,
    plain_hex: str | None = None,
    preset_file: Path | None = None,
    offset: int | None = None,
    extra: list[str] | None = None,
    extra_text: list[str] | None = None,
    extra_hex: list[str] | None = None,
    encoding: str = "utf-8",
) -> ResolvedPlaintextPreset:
    preset_info = (
        _load_custom_preset(preset_file, encoding)
        if preset_file is not None
        else _get_preset(preset)
    )
    override = _plain_override(plain_file, plain_text, plain_hex, encoding)
    if preset_info.requires_text:
        if override is None:
            raise ValueError(f"{preset_info.name} 预设需要 --plain-text 或 --plain-hex")
        plain_bytes = override
    elif preset_info.requires_inner_name:
        if override is not None:
            plain_bytes = override
        else:
            plain_bytes = (inner_name or "flag.txt").encode(encoding)
    else:
        plain_bytes = override if override is not None else preset_info.plain_bytes
    resolved_offset = preset_info.default_offset if offset is None else offset
    extra_items = [f"{item_offset}:{item.hex()}" for item_offset, item in preset_info.extra]
    extra_items.extend(extra or [])
    extra_items.extend(extra_hex or [])
    for item in extra_text or []:
        item_offset, text = _split_extra_text(item)
        extra_items.append(f"{item_offset}:{text.encode(encoding).hex()}")
    _validate_known_plaintext(plain_bytes, extra_items)
    return ResolvedPlaintextPreset(
        name=preset_info.name,
        description=preset_info.description,
        plain_bytes=plain_bytes,
        offset=resolved_offset,
        extra=extra_items,
    )


def recover_password_from_keys(
    cipher_zip: Path,
    keys: tuple[str, str, str],
    *,
    charset: str = "?l?u?d",
    length: str | None = None,
    mask: str | None = None,
    jobs: int = 0,
    bkcrack: Path | None = None,
) -> ZipPlaintextResult:
    _check_file(cipher_zip, "加密 ZIP")
    _ = (jobs, bkcrack)
    norm_keys = [_normalize_key(part) for part in keys]
    target_keys = tuple(int(part, 16) for part in norm_keys)
    command = ["native-bkcrack", "-C", str(cipher_zip), "-k", *norm_keys]
    if mask:
        command.extend(["-m", mask])
    else:
        command.extend(["-b", charset])
        if length:
            command.extend(["-l", length])
    attempts = 0
    password = ""
    for attempts, candidate in enumerate(
        _iter_password_candidates(charset=charset, length=length, mask=mask), 1
    ):
        if _keys_from_password(candidate.encode("utf-8")) == target_keys:
            password = candidate
            break
    stdout = f"Password: {password}\nAttempts: {attempts}" if password else f"Attempts: {attempts}"
    return ZipPlaintextResult(
        operation="zip.plaintext.recover-password",
        input_path=str(cipher_zip),
        output_path="-",
        output_paths=[],
        tool_path="native-python",
        mode="recover-password",
        cipher_entry="-",
        plain_source="keys",
        offset=None,
        keys=norm_keys,
        new_password=password,
        decrypted=False,
        changed_password=False,
        command=command,
        stdout=stdout,
        stderr="",
        written_bytes=0,
    )


def _get_preset(name: str) -> PlaintextPreset:
    key = name.strip().lower().replace("_", "-")
    try:
        return PLAINTEXT_PRESET_ALIASES[key]
    except KeyError as error:
        raise ValueError(f"preset 必须是 {', '.join(PLAINTEXT_PRESET_NAMES)}") from error


def _load_custom_preset(path: Path, encoding: str) -> PlaintextPreset:
    _check_file(path, "自定义预设文件")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("自定义预设文件必须是 JSON object")
    name = str(data.get("name") or Path(path).stem or "custom")
    description = str(data.get("description") or f"自定义预设：{name}")
    default_offset = int(data.get("offset", data.get("default_offset", 0)))
    plain = _plain_override_from_json(data, Path(path).parent, encoding)
    extra_pairs: list[tuple[int, bytes]] = []
    for item in _as_string_list(data.get("extra")) + _as_string_list(data.get("extra_hex")):
        item_offset, value = _parse_extra(item)
        extra_pairs.append((item_offset, bytes.fromhex(value)))
    for item in _as_string_list(data.get("extra_text")):
        item_offset, text = _split_extra_text(item)
        extra_pairs.append((item_offset, text.encode(encoding)))
    aliases = tuple(_as_string_list(data.get("aliases")))
    return PlaintextPreset(
        name,
        aliases,
        description,
        default_offset,
        plain,
        tuple(extra_pairs),
        requires_text=not plain,
    )


def _plain_override_from_json(data: dict[str, object], base_dir: Path, encoding: str) -> bytes:
    provided = [
        key for key in ("plain_file", "plain_text", "plain_hex") if data.get(key) is not None
    ]
    if len(provided) > 1:
        raise ValueError("自定义预设 plain_file/plain_text/plain_hex 只能提供一个")
    if not provided:
        return b""
    if "plain_file" in provided:
        plain_path = Path(str(data["plain_file"]))
        if not plain_path.is_absolute():
            plain_path = base_dir / plain_path
        _check_file(plain_path, "自定义明文文件")
        return plain_path.read_bytes()
    if "plain_text" in provided:
        return str(data["plain_text"]).encode(encoding)
    return _parse_hex_bytes(str(data["plain_hex"]), "plain_hex")


def _as_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ValueError("自定义预设列表字段必须是字符串或字符串数组")


def _plain_override(
    plain_file: Path | None, plain_text: str | None, plain_hex: str | None, encoding: str
) -> bytes | None:
    provided = [value is not None for value in (plain_file, plain_text, plain_hex)].count(True)
    if provided > 1:
        raise ValueError("--plain-file/--plain-text/--plain-hex 只能提供一个")
    if plain_file is not None:
        _check_file(plain_file, "自定义明文文件")
        return plain_file.read_bytes()
    if plain_text is not None:
        return plain_text.encode(encoding)
    if plain_hex is None:
        return None
    return _parse_hex_bytes(plain_hex, "--plain-hex")


def _parse_hex_bytes(value: str, label: str) -> bytes:
    data = value.strip().lower().removeprefix("0x")
    if len(data) % 2 or not re.fullmatch(r"[0-9a-f]*", data):
        raise ValueError(f"{label} 必须是偶数字节十六进制")
    return bytes.fromhex(data)


def _split_extra_text(value: str) -> tuple[int, str]:
    if ":" not in value:
        raise ValueError("--extra-text 格式必须是 OFFSET:TEXT，例如 29:74f6")
    offset, text = value.split(":", 1)
    return int(offset, 0), text


def _validate_known_plaintext(plain_bytes: bytes, extra_items: list[str]) -> None:
    if len(plain_bytes) < 8:
        raise ValueError("明文攻击至少需要一段连续 8 字节明文")
    total = len(plain_bytes)
    for item in extra_items:
        _, data = _parse_extra(item)
        total += len(bytes.fromhex(data))
    if total < 12:
        raise ValueError("明文攻击总共至少需要 12 字节已知明文；可用 --extra 或 --extra-text 补足")


def _parse_extra(value: str) -> tuple[int, str]:
    if ":" not in value:
        raise ValueError("--extra 格式必须是 OFFSET:HEX，例如 0:89504e47")
    offset, data = value.split(":", 1)
    data = data.strip().lower().removeprefix("0x")
    if len(data) % 2 or not re.fullmatch(r"[0-9a-f]*", data):
        raise ValueError("--extra 的 HEX 部分必须是偶数字节十六进制")
    return int(offset, 0), data


def _normalize_key(value: str) -> str:
    text = value.strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{8}", text):
        raise ValueError(f"key 必须是 8 位十六进制：{value}")
    return text


def _select_encrypted_entry(zip_path: Path) -> str:
    with zipfile.ZipFile(zip_path) as archive:
        entries = [
            info.filename for info in archive.infolist() if info.flag_bits & 1 and not info.is_dir()
        ]
    if not entries:
        raise ValueError("ZIP 内没有 ZipCrypto 加密条目")
    if len(entries) > 1:
        raise ValueError("存在多个加密条目，请用 --entry 指定目标文件")
    return entries[0]


@dataclass(frozen=True)
class _ZipCipherTarget:
    info: zipfile.ZipInfo
    ciphertext: bytes
    check_byte: int | None


@dataclass(frozen=True)
class _PlainZipEntry:
    name: str
    data: bytes
    date_time: tuple[int, int, int, int, int, int]
    external_attr: int
    is_dir: bool = False


@dataclass
class _AttackData:
    ciphertext: bytes
    plaintext: bytearray
    keystream: bytes
    offset: int
    extra_plaintext: list[tuple[int, int]]


_U32 = 0xFFFFFFFF
_MULT = 0x08088405
_MULT_INV = 0xD94FA8CD
_MASK_2_32 = 0xFFFFFFFC
_MASK_8_32 = 0xFFFFFF00
_MASK_10_32 = 0xFFFFFC00
_MASK_24_32 = 0xFF000000
_MASK_26_32 = 0xFC000000
_MAXDIFF_24 = ((1 << 24) - 1) + 0xFF
_MAXDIFF_26 = ((1 << 26) - 1) + 0xFF
_ENCRYPTION_HEADER_SIZE = 12


def _recover_keys_known_plaintext(
    ciphertext: bytes,
    check_byte: int | None,
    plaintext: bytes,
    offset: int,
    extra_plaintext: dict[int, int],
    *,
    jobs: int = 0,
) -> tuple[int, int, int]:
    _ = jobs
    data = _prepare_attack_data(ciphertext, check_byte, plaintext, offset, extra_plaintext)
    candidates, index = _reduce_z_candidates(data.keystream)
    attack = _NativeBkcrackAttack(data, index)
    for candidate in candidates:
        attack.carryout(candidate)
        if attack.solutions:
            return attack.solutions[0]
    raise ValueError("原生 bkcrack 未恢复出三段密钥；请检查明文、偏移或 ZipCrypto 条件")


def _prepare_attack_data(
    ciphertext: bytes,
    check_byte: int | None,
    plaintext: bytes,
    offset_arg: int,
    extra_plaintext_arg: dict[int, int],
) -> _AttackData:
    if len(ciphertext) < 12:
        raise ValueError("ciphertext 太短，至少需要 12 字节 ZipCrypto 加密头")
    if offset_arg < -_ENCRYPTION_HEADER_SIZE:
        raise ValueError("明文 offset 太小")
    offset = _ENCRYPTION_HEADER_SIZE + offset_arg
    if offset < 0 or offset + len(plaintext) > len(ciphertext):
        raise ValueError("明文 offset 超出密文范围")
    extra = dict(extra_plaintext_arg)
    if check_byte is not None and -1 not in extra and not (offset <= 11 < offset + len(plaintext)):
        extra[-1] = check_byte
    extra_abs = {
        _ENCRYPTION_HEADER_SIZE + item_offset: value for item_offset, value in extra.items()
    }
    if extra_abs and min(extra_abs) < 0:
        raise ValueError("extra plaintext offset 太小")
    if extra_abs and max(extra_abs) >= len(ciphertext):
        raise ValueError("extra plaintext offset 太大")

    plain = bytearray(plaintext)
    for extra_offset, extra_byte in list(extra_abs.items()):
        if offset <= extra_offset < offset + len(plain):
            plain[extra_offset - offset] = extra_byte
            del extra_abs[extra_offset]
    while offset - 1 in extra_abs:
        offset -= 1
        plain.insert(0, extra_abs.pop(offset))
    while offset + len(plain) in extra_abs:
        plain.append(extra_abs.pop(offset + len(plain)))
    if len(plain) < 8:
        raise ValueError(
            f"not enough contiguous plaintext ({len(plain)} bytes available, minimum is 8)"
        )
    if len(plain) + len(extra_abs) < 12:
        raise ValueError(
            f"not enough plaintext ({len(plain) + len(extra_abs)} bytes available, minimum is 12)"
        )
    ordered_extra = sorted(extra_abs.items(), key=lambda item: abs(item[0] - (offset + 8)))
    keystream = bytes(p ^ c for p, c in zip(plain, ciphertext[offset : offset + len(plain)]))
    return _AttackData(ciphertext, plain, keystream, offset, ordered_extra)


class _NativeBkcrackAttack:
    """Pure Python port of bkcrack's Attack/Z-reduction key search."""

    def __init__(self, data: _AttackData, index: int) -> None:
        self.data = data
        self.index = index + 1 - 8
        self.zlist = [0] * 8
        self.ylist = [0] * 8
        self.xlist = [0] * 8
        self.solutions: list[tuple[int, int, int]] = []

    def carryout(self, z7_2_32: int) -> None:
        self.zlist[7] = z7_2_32
        self._explore_zlists(7)

    def _explore_zlists(self, i: int) -> None:
        if self.solutions:
            return
        if i != 0:
            _, _, keystream_inv, _, _ = _bkcrack_tables()
            zim1_10_32 = _get_zim1_10_32(self.zlist[i])
            bucket = (zim1_10_32 & 0xFFFF) >> 10
            for zim1_2_16 in keystream_inv[self.data.keystream[self.index + i - 1]][bucket]:
                self.zlist[i - 1] = zim1_10_32 | zim1_2_16
                self.zlist[i] &= _MASK_2_32
                self.zlist[i] = _u32(
                    self.zlist[i] | ((_crc32inv(self.zlist[i], 0) ^ self.zlist[i - 1]) >> 8)
                )
                if i < 7:
                    self.ylist[i + 1] = _get_yi_24_32(self.zlist[i + 1], self.zlist[i])
                self._explore_zlists(i - 1)
                if self.solutions:
                    return
        else:
            _, _, _, _, msb_fiber3 = _bkcrack_tables()
            prod = _u32(((_MULT_INV * _msb(self.ylist[7])) << 24) - _MULT_INV)
            y7_8_24 = 0
            while y7_8_24 < (1 << 24):
                for y7_0_8 in msb_fiber3[(_msb(self.ylist[6]) - _msb(prod)) & 0xFF]:
                    if (
                        _u32(prod + _MULT_INV * y7_0_8 - (self.ylist[6] & _MASK_24_32))
                        <= _MAXDIFF_24
                    ):
                        self.ylist[7] = y7_0_8 | y7_8_24 | (self.ylist[7] & _MASK_24_32)
                        self._explore_ylists(7)
                        if self.solutions:
                            return
                y7_8_24 += 1 << 8
                prod = _u32(prod + (_MULT_INV << 8))

    def _explore_ylists(self, i: int) -> None:
        if self.solutions:
            return
        if i != 3:
            _, _, _, msb_fiber2, _ = _bkcrack_tables()
            fy = _u32((self.ylist[i] - 1) * _MULT_INV)
            ffy = _u32((fy - 1) * _MULT_INV)
            fiber_index = _msb(_u32(ffy - (self.ylist[i - 2] & _MASK_24_32)))
            for xi_0_8 in msb_fiber2[fiber_index]:
                yim1 = _u32(fy - xi_0_8)
                if _u32(
                    ffy - _MULT_INV * xi_0_8 - (self.ylist[i - 2] & _MASK_24_32)
                ) <= _MAXDIFF_24 and _msb(yim1) == _msb(self.ylist[i - 1]):
                    self.ylist[i - 1] = yim1
                    self.xlist[i] = xi_0_8
                    self._explore_ylists(i - 1)
                    if self.solutions:
                        return
        else:
            self._test_xlist()

    def _test_xlist(self) -> None:
        data = self.data
        index = self.index
        xlist = self.xlist.copy()
        for i in range(5, 8):
            xlist[i] = (_crc32(xlist[i - 1], data.plaintext[index + i - 1]) & _MASK_8_32) | (
                xlist[i] & 0xFF
            )
        x_value = xlist[7]
        for i in range(6, 2, -1):
            x_value = _crc32inv(x_value, data.plaintext[index + i])
        y1_26_32 = _get_yi_24_32(self.zlist[1], self.zlist[0]) & _MASK_26_32
        if (
            _u32(
                _u32(_u32((self.ylist[3] - 1) * _MULT_INV) - (x_value & 0xFF) - 1) * _MULT_INV
                - y1_26_32
            )
            > _MAXDIFF_26
        ):
            return

        keys_forward = (xlist[7], self.ylist[7], self.zlist[7])
        keys_forward = _keys_update(keys_forward, data.plaintext[index + 7])
        for plain_index in range(index + 8, len(data.plaintext)):
            cipher_byte = data.ciphertext[data.offset + plain_index]
            if (cipher_byte ^ _keys_stream_byte(keys_forward)) != data.plaintext[plain_index]:
                return
            keys_forward = _keys_update(keys_forward, data.plaintext[plain_index])
        index_forward = data.offset + len(data.plaintext)

        keys_backward = (x_value, self.ylist[3], self.zlist[3])
        for plain_index in range(index + 2, -1, -1):
            cipher_byte = data.ciphertext[data.offset + plain_index]
            keys_backward = _keys_update_backward(keys_backward, cipher_byte)
            if (cipher_byte ^ _keys_stream_byte(keys_backward)) != data.plaintext[plain_index]:
                return
        index_backward = data.offset

        for extra_index, extra_byte in data.extra_plaintext:
            if extra_index < index_backward:
                keys_backward = _keys_update_backward_range(
                    keys_backward, data.ciphertext, index_backward, extra_index
                )
                index_backward = extra_index
                plain_byte = data.ciphertext[index_backward] ^ _keys_stream_byte(keys_backward)
            else:
                keys_forward = _keys_update_range(
                    keys_forward, data.ciphertext, index_forward, extra_index
                )
                index_forward = extra_index
                plain_byte = data.ciphertext[index_forward] ^ _keys_stream_byte(keys_forward)
            if plain_byte != extra_byte:
                return

        keys_backward = _keys_update_backward_range(
            keys_backward, data.ciphertext, index_backward, 0
        )
        self.solutions.append(keys_backward)


def _reduce_z_candidates(keystream: bytes) -> tuple[list[int], int]:
    _, exists, inv, _, _ = _bkcrack_tables()
    index = len(keystream) - 1
    zi_vector = [
        shifted << 10 for shifted in range(1 << 22) if exists[keystream[index]][shifted & 0x3F]
    ]
    tracking = False
    best_copy: list[int] = []
    best_index = index
    best_size = 1 << 16
    waiting = False
    wait = 0
    for i in range(index, 7, -1):
        zim1_vector: list[int] = []
        zim1_vector_append = zim1_vector.append
        seen = bytearray(1 << 22)
        number_of_zim1_2_32 = 0
        ki = keystream[i]
        kim1 = keystream[i - 1]
        inv_ki = inv[ki]
        inv_kim1 = inv[kim1]
        exists_kim1 = exists[kim1]
        for zi_10_32 in zi_vector:
            for zi_2_16 in inv_ki[(zi_10_32 & 0xFFFF) >> 10]:
                zim1_10_32 = _get_zim1_10_32(zi_10_32 | zi_2_16)
                seen_index = zim1_10_32 >> 10
                if not seen[seen_index] and exists_kim1[(zim1_10_32 & 0xFFFF) >> 10]:
                    seen[seen_index] = 1
                    zim1_vector_append(zim1_10_32)
                    number_of_zim1_2_32 += len(inv_kim1[(zim1_10_32 & 0xFFFF) >> 10])
        if number_of_zim1_2_32 <= best_size:
            tracking = True
            best_index = i - 1
            best_size = number_of_zim1_2_32
            waiting = False
        elif tracking:
            if best_index == i:
                best_copy = zi_vector.copy()
                if best_size <= 1 << 8:
                    waiting = True
                    wait = best_size * 4
            if waiting:
                wait -= 1
                if wait == 0:
                    break
        zi_vector = zim1_vector
    if tracking:
        if best_index != 7:
            zi_vector = best_copy
        index = best_index
    else:
        index = 7
    candidates: list[int] = []
    append = candidates.append
    for zi_10_32 in zi_vector:
        zi_2_16_vector = inv[keystream[index]][(zi_10_32 & 0xFFFF) >> 10]
        for zi_2_16 in zi_2_16_vector:
            append(zi_10_32 | zi_2_16)
    return candidates, index


@lru_cache(maxsize=1)
def _bkcrack_tables() -> tuple[
    list[int], list[list[bool]], list[list[list[int]]], list[list[int]], list[list[int]]
]:
    crc_table = [0] * 256
    crc_inverse_table = [0] * 256
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        crc &= _U32
        crc_table[value] = crc
        crc_inverse_table[_msb(crc)] = _u32((crc << 8) ^ value)
    keystream_inverse = [[[] for _ in range(64)] for _ in range(256)]
    keystream_exists = [[False] * 64 for _ in range(256)]
    for z_2_16 in range(0, 1 << 16, 4):
        stream_byte = _lsb(((z_2_16 | 2) * (z_2_16 | 3)) >> 8)
        bucket = z_2_16 >> 10
        keystream_inverse[stream_byte][bucket].append(z_2_16)
        keystream_exists[stream_byte][bucket] = True
    msb_fiber2 = [[] for _ in range(256)]
    msb_fiber3 = [[] for _ in range(256)]
    product_inverse = 0
    for value in range(256):
        top = _msb(product_inverse)
        msb_fiber2[top].append(value)
        msb_fiber2[(top + 1) & 0xFF].append(value)
        msb_fiber3[(top - 1) & 0xFF].append(value)
        msb_fiber3[top].append(value)
        msb_fiber3[(top + 1) & 0xFF].append(value)
        product_inverse = _u32(product_inverse + _MULT_INV)
    _CRC32_TABLE[:] = crc_table
    _CRC32_INV_TABLE[:] = crc_inverse_table
    return crc_table, keystream_exists, keystream_inverse, msb_fiber2, msb_fiber3


_CRC32_TABLE = [0] * 256
_CRC32_INV_TABLE = [0] * 256


def _u32(value: int) -> int:
    return value & _U32


def _lsb(value: int) -> int:
    return value & 0xFF


def _msb(value: int) -> int:
    return (value >> 24) & 0xFF


def _crc32(previous: int, byte: int) -> int:
    if _CRC32_TABLE[1] == 0:
        _bkcrack_tables()
    return _u32((previous >> 8) ^ _CRC32_TABLE[(previous & 0xFF) ^ byte])


def _crc32inv(crc: int, byte: int) -> int:
    if _CRC32_INV_TABLE[1] == 0:
        _bkcrack_tables()
    return _u32((crc << 8) ^ _CRC32_INV_TABLE[_msb(crc)] ^ byte)


def _get_yi_24_32(zi: int, zim1: int) -> int:
    return _u32((_crc32inv(zi, 0) ^ zim1) << 24)


def _get_zim1_10_32(zi_2_32: int) -> int:
    return _crc32inv(zi_2_32, 0) & _MASK_10_32


def _keys_from_password(password: bytes) -> tuple[int, int, int]:
    keys = (0x12345678, 0x23456789, 0x34567890)
    for value in password:
        keys = _keys_update(keys, value)
    return keys


def _keys_update(keys: tuple[int, int, int], plain_byte: int) -> tuple[int, int, int]:
    x, y, z = keys
    x = _crc32(x, plain_byte)
    y = _u32((y + _lsb(x)) * _MULT + 1)
    z = _crc32(z, _msb(y))
    return x, y, z


def _keys_update_backward(keys: tuple[int, int, int], cipher_byte: int) -> tuple[int, int, int]:
    x, y, z = keys
    z = _crc32inv(z, _msb(y))
    y = _u32((y - 1) * _MULT_INV - _lsb(x))
    x = _crc32inv(x, cipher_byte ^ _keys_stream_byte((x, y, z)))
    return x, y, z


def _keys_stream_byte(keys: tuple[int, int, int]) -> int:
    _, _, z = keys
    temp = z | 2
    return _lsb((temp * (temp ^ 1)) >> 8)


def _keys_update_range(
    keys: tuple[int, int, int], ciphertext: bytes, current: int, target: int
) -> tuple[int, int, int]:
    for cipher_byte in ciphertext[current:target]:
        keys = _keys_update(keys, cipher_byte ^ _keys_stream_byte(keys))
    return keys


def _keys_update_backward_range(
    keys: tuple[int, int, int], ciphertext: bytes, current: int, target: int
) -> tuple[int, int, int]:
    for cipher_byte in reversed(ciphertext[target:current]):
        keys = _keys_update_backward(keys, cipher_byte)
    return keys


def _zipcrypto_decrypt(keys: tuple[int, int, int], payload: bytes) -> bytes:
    out = bytearray()
    for cipher_byte in payload:
        plain_byte = cipher_byte ^ _keys_stream_byte(keys)
        keys = _keys_update(keys, plain_byte)
        out.append(plain_byte)
    return bytes(out)


def _zipcrypto_encrypt(keys: tuple[int, int, int], payload: bytes) -> bytes:
    out = bytearray()
    for plain_byte in payload:
        out.append(plain_byte ^ _keys_stream_byte(keys))
        keys = _keys_update(keys, plain_byte)
    return bytes(out)


def _read_zip_cipher_target(zip_path: Path, entry: str) -> _ZipCipherTarget:
    with zipfile.ZipFile(zip_path) as archive:
        info = archive.getinfo(entry)
        if not info.flag_bits & 0x01:
            raise ValueError(f"ZIP 条目未使用 ZipCrypto 加密：{entry}")
        if info.compress_type == 99:
            raise ValueError("检测到 WinZip AES，bkcrack 原生后端只支持 ZipCrypto")
        ciphertext = _read_zip_entry_payload(zip_path, entry)
        return _ZipCipherTarget(info, ciphertext, _zip_check_byte(info))


def _read_zip_entry_payload(zip_path: Path, entry: str) -> bytes:
    with zipfile.ZipFile(zip_path) as archive:
        info = archive.getinfo(entry)
    with Path(zip_path).open("rb") as handle:
        handle.seek(info.header_offset)
        header = handle.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise ValueError("ZIP 本地文件头异常")
        name_len = int.from_bytes(header[26:28], "little")
        extra_len = int.from_bytes(header[28:30], "little")
        handle.seek(name_len + extra_len, 1)
        return handle.read(info.compress_size)


def _zip_check_byte(info: zipfile.ZipInfo) -> int:
    return ((info._raw_time >> 8) & 0xFF) if info.flag_bits & 0x08 else ((info.CRC >> 24) & 0xFF)


def _rewrite_archive_with_keys(
    cipher_zip: Path,
    output: Path,
    keys: tuple[str, str, str],
    *,
    new_password: str | None,
    keep_header: bool,
) -> None:
    key_tuple = tuple(int(part, 16) for part in keys)
    entries: list[_PlainZipEntry] = []
    with zipfile.ZipFile(cipher_zip) as archive:
        for info in archive.infolist():
            if info.is_dir():
                entries.append(
                    _PlainZipEntry(
                        info.filename, b"", info.date_time, info.external_attr, is_dir=True
                    )
                )
                continue
            if info.flag_bits & 0x01:
                encrypted = _read_zip_entry_payload(cipher_zip, info.filename)
                decrypted = _zipcrypto_decrypt(key_tuple, encrypted)
                payload = decrypted if keep_header else decrypted[12:]
                data = (
                    payload if keep_header else _decompress_zip_payload(payload, info.compress_type)
                )
            else:
                data = archive.read(info.filename)
            entries.append(_PlainZipEntry(info.filename, data, info.date_time, info.external_attr))
    _write_zip_entries(output, entries, password=new_password)


def _decompress_zip_payload(payload: bytes, compression_method: int) -> bytes:
    if compression_method == zipfile.ZIP_STORED:
        return payload
    if compression_method == zipfile.ZIP_DEFLATED:
        return zlib.decompress(payload, -15)
    if compression_method == zipfile.ZIP_BZIP2:
        import bz2

        return bz2.decompress(payload)
    if compression_method == zipfile.ZIP_LZMA:
        import lzma

        return lzma.decompress(payload)
    raise ValueError(f"暂不支持转换 ZIP 压缩方法：{compression_method}")


def _write_zip_entries(
    output: Path, entries: list[_PlainZipEntry], *, password: str | None
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if password is None:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            for entry in entries:
                info = zipfile.ZipInfo(
                    _dir_name(entry.name) if entry.is_dir else entry.name, entry.date_time
                )
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = entry.external_attr or (
                    (0o40775 if entry.is_dir else 0o600) << 16
                )
                archive.writestr(info, b"" if entry.is_dir else entry.data)
        return

    central_records: list[bytes] = []
    offset = 0
    with output.open("wb") as handle:
        for entry in entries:
            name = _dir_name(entry.name) if entry.is_dir else entry.name
            name_bytes = name.encode("utf-8")
            data = b"" if entry.is_dir else entry.data
            encrypted = password is not None and not entry.is_dir
            flag_bits = 0x0800 | (0x0001 if encrypted else 0)
            method = zipfile.ZIP_STORED
            crc = binascii.crc32(data) & _U32
            payload = data
            if encrypted:
                header = _encryption_header(name, crc)
                payload = _zipcrypto_encrypt(
                    _keys_from_password(password.encode("utf-8")), header + data
                )
            compressed_size = len(payload)
            uncompressed_size = len(data)
            dos_time, dos_date = _dos_datetime(entry.date_time)
            local_offset = offset
            local = struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                flag_bits,
                method,
                dos_time,
                dos_date,
                crc,
                compressed_size,
                uncompressed_size,
                len(name_bytes),
                0,
            )
            handle.write(local)
            handle.write(name_bytes)
            handle.write(payload)
            offset += len(local) + len(name_bytes) + len(payload)
            external_attr = entry.external_attr or ((0o40775 if entry.is_dir else 0o600) << 16)
            central_records.append(
                struct.pack(
                    "<IHHHHHHIIIHHHHHII",
                    0x02014B50,
                    20,
                    20,
                    flag_bits,
                    method,
                    dos_time,
                    dos_date,
                    crc,
                    compressed_size,
                    uncompressed_size,
                    len(name_bytes),
                    0,
                    0,
                    0,
                    0,
                    external_attr,
                    local_offset,
                )
                + name_bytes
            )
        central_offset = offset
        for record in central_records:
            handle.write(record)
            offset += len(record)
        central_size = offset - central_offset
        handle.write(
            struct.pack(
                "<IHHHHIIH",
                0x06054B50,
                0,
                0,
                len(central_records),
                len(central_records),
                central_size,
                central_offset,
                0,
            )
        )


def _encryption_header(name: str, crc: int) -> bytes:
    seed = binascii.crc32(name.encode("utf-8")) & _U32
    header = bytearray()
    for _ in range(11):
        seed = _u32(seed * 1103515245 + 12345)
        header.append((seed >> 16) & 0xFF)
    header.append((crc >> 24) & 0xFF)
    return bytes(header)


def _dir_name(name: str) -> str:
    return name if name.endswith("/") else name + "/"


def _dos_datetime(date_time: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    year, month, day, hour, minute, second = date_time
    year = min(max(year, 1980), 2107)
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    return dos_time, dos_date


def _expand_extra_plaintext(items: list[str]) -> dict[int, int]:
    expanded: dict[int, int] = {}
    for item in items:
        offset, value = _parse_extra(item)
        data = bytes.fromhex(value)
        for index, byte in enumerate(data):
            expanded[offset + index] = byte
    return expanded


def _iter_password_candidates(
    *, charset: str, length: str | None, mask: str | None
) -> Iterable[str]:
    if mask:
        alphabets = _parse_password_mask(mask)
        for item in itertools.product(*alphabets):
            yield "".join(item)
        return
    alphabet = _expand_password_charset(charset)
    min_length, max_length = _parse_length_range(length)
    for size in range(min_length, max_length + 1):
        for item in itertools.product(alphabet, repeat=size):
            yield "".join(item)


def _parse_password_mask(mask: str) -> list[str]:
    alphabets: list[str] = []
    index = 0
    while index < len(mask):
        if mask[index] == "?" and index + 1 < len(mask):
            alphabets.append(_mask_alphabet(mask[index + 1]))
            index += 2
        else:
            alphabets.append(mask[index])
            index += 1
    return alphabets


def _expand_password_charset(charset: str) -> str:
    if "?" not in charset:
        return "".join(dict.fromkeys(charset))
    output = ""
    index = 0
    while index < len(charset):
        if charset[index] == "?" and index + 1 < len(charset):
            output += _mask_alphabet(charset[index + 1])
            index += 2
        else:
            output += charset[index]
            index += 1
    return "".join(dict.fromkeys(output))


def _mask_alphabet(code: str) -> str:
    if code == "l":
        return "abcdefghijklmnopqrstuvwxyz"
    if code == "u":
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if code == "d":
        return "0123456789"
    if code == "x":
        return "0123456789abcdef"
    if code == "s":
        return " !\"#$%&'()*+,-./:;<=>@[\\]^_`{|}~"
    if code == "a":
        return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    raise ValueError(f"不支持的密码掩码：?{code}")


def _parse_length_range(length: str | None) -> tuple[int, int]:
    if not length:
        return 0, 6
    text = length.strip()
    if ".." in text:
        left, right = text.split("..", 1)
        minimum = int(left) if left else 0
        maximum = int(right) if right else 6
    else:
        minimum = maximum = int(text)
    if minimum < 0 or maximum < minimum:
        raise ValueError("密码长度范围无效")
    return minimum, maximum


def _format_key(value: int) -> str:
    return f"{value & _U32:08x}"


def _check_file(path: Path, label: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
