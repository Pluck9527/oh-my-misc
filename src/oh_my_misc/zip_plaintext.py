from __future__ import annotations

import json
import re
import shutil
import subprocess
import zipfile
from dataclasses import asdict, dataclass, replace
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
    PlaintextPreset("png", ("png-header",), "PNG 文件头：89504e470d0a1a0a0000000d49484452，偏移 0", 0, _PNG_HEADER),
    PlaintextPreset(
        "zip",
        ("inner-zip", "zip-local"),
        "内层 ZIP：默认已知本地文件头 PK0304@0 和内层文件名 flag.txt@30，可用 --inner-name 覆盖",
        30,
        extra=((0, b"PK\x03\x04"),),
        requires_inner_name=True,
    ),
    PlaintextPreset("exe", ("dos-stub", "pe"), "EXE DOS stub 固定字符串，偏移 64", 64, _EXE_DOS_STUB),
    PlaintextPreset("pcapng", ("pcap",), "PCAPNG section/header 特征字节，偏移 6", 6, _PCAPNG_BYTES),
    PlaintextPreset("xml", ("web.xml",), "XML 声明：<?xml version=...?>，偏移 0", 0, _XML_HEADER),
    PlaintextPreset("svg", ("svg-xml",), "SVG/XML 开头：<?xml version=\"1.0\" ，偏移 0", 0, _SVG_HEADER),
    PlaintextPreset("vmdk", ("vmware",), "VMDK magic/descriptor 开头：KDMV...，偏移 0", 0, _VMDK_HEADER),
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
    tool = _find_bkcrack(bkcrack)
    entry = cipher_entry or ("-" if keys is not None else _select_encrypted_entry(cipher_zip))
    plain_source = "keys"
    if keys is None:
        if plain_zip is not None:
            _check_file(plain_zip, "已知明文 ZIP")
            plain_name = plain_entry or (plain_file.name if plain_file is not None else entry)
            command = [
                tool,
                "-C",
                str(cipher_zip),
                "-c",
                entry,
                "-P",
                str(plain_zip),
                "-p",
                plain_name,
            ]
            plain_source = f"{plain_zip}:{plain_name}"
        else:
            if plain_file is None:
                raise ValueError("明文攻击需要 --plain-file/--plain-zip，或直接提供 --keys")
            _check_file(plain_file, "已知明文文件")
            command = [tool, "-C", str(cipher_zip), "-c", entry, "-p", str(plain_file)]
            plain_source = str(plain_file)
        if offset is not None:
            command.extend(["-o", str(offset)])
        if truncate is not None:
            command.extend(["-t", str(truncate)])
        if ignore_check_byte:
            command.append("--ignore-check-byte")
        for item in extra or []:
            off, value = _parse_extra(item)
            command.extend(["-x", str(off), value])
        if jobs > 0:
            command.extend(["-j", str(jobs)])
        proc = _run(command)
        found_keys = _extract_keys(proc.stdout + "\n" + proc.stderr)
    else:
        found_keys = [_normalize_key(part) for part in keys]
        command = [tool, "-C", str(cipher_zip), "-c", entry, "-k", *found_keys]
        proc = subprocess.CompletedProcess(command, 0, "", "")
    if len(found_keys) != 3:
        raise ValueError("bkcrack 未返回三段密钥；请检查明文、偏移或 ZipCrypto 条件")

    output_paths: list[str] = []
    written = 0
    changed_password = False
    decrypted_done = False
    action_command: list[str] = []
    action_stdout = ""
    action_stderr = ""
    if output is not None:
        if decrypt:
            action_command = [tool, "-C", str(cipher_zip), "-k", *found_keys, "-D", str(output)]
            mode = "decrypt"
            decrypted_done = True
        else:
            password = "" if new_password is None else new_password
            action_command = [
                tool,
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
        if keep_header and decrypt:
            action_command.append("--keep-header")
        action_proc = _run(action_command)
        action_stdout = action_proc.stdout
        action_stderr = action_proc.stderr
        if output.exists():
            output_paths = [str(output)]
            written = output.stat().st_size if output.is_file() else 0
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
        stdout=(action_stdout or proc.stdout)[-4000:],
        stderr=(action_stderr or proc.stderr)[-4000:],
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
    preset_info = _load_custom_preset(preset_file, encoding) if preset_file is not None else _get_preset(preset)
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
    tool = _find_bkcrack(bkcrack)
    norm_keys = [_normalize_key(part) for part in keys]
    if mask:
        command = [tool, "-C", str(cipher_zip), "-k", *norm_keys, "-m", mask]
    else:
        command = [tool, "-C", str(cipher_zip), "-k", *norm_keys, "-b", charset]
        if length:
            command.extend(["-l", length])
    if jobs > 0:
        command.extend(["-j", str(jobs)])
    proc = _run(command)
    password = _extract_password(proc.stdout + "\n" + proc.stderr)
    return ZipPlaintextResult(
        operation="zip.plaintext.recover-password",
        input_path=str(cipher_zip),
        output_path="-",
        output_paths=[],
        tool_path=tool,
        mode="recover-password",
        cipher_entry="-",
        plain_source="keys",
        offset=None,
        keys=norm_keys,
        new_password=password,
        decrypted=False,
        changed_password=False,
        command=command,
        stdout=proc.stdout[-4000:],
        stderr=proc.stderr[-4000:],
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



def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise ValueError(
            "bkcrack 执行失败："
            + " ".join(command)
            + "\n"
            + (proc.stdout[-2000:] + proc.stderr[-2000:])
        )
    return proc


def _select_encrypted_entry(zip_path: Path) -> str:
    with zipfile.ZipFile(zip_path) as archive:
        entries = [info.filename for info in archive.infolist() if info.flag_bits & 1 and not info.is_dir()]
    if not entries:
        raise ValueError("ZIP 内没有 ZipCrypto 加密条目")
    if len(entries) > 1:
        raise ValueError("存在多个加密条目，请用 --entry 指定目标文件")
    return entries[0]


def _extract_keys(text: str) -> list[str]:
    matches = re.findall(r"\b([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\b", text)
    if not matches:
        return []
    return [part.lower() for part in matches[-1]]


def _extract_password(text: str) -> str:
    patterns = [
        r"Password\s*:\s*(.+)",
        r"password\s*is\s*:?\s*(.+)",
        r"Found\s+password\s*:?\s*(.+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip().strip("'")
    return ""


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


def _find_bkcrack(path: Path | None) -> str:
    if path is not None:
        _check_file(path, "bkcrack 可执行文件")
        return str(path)
    found = shutil.which("bkcrack")
    if found:
        return found
    raise ValueError("未找到 bkcrack；请安装 bkcrack 或用 --bkcrack 指定路径")


def _check_file(path: Path, label: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
