from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from pathlib import Path

CLOAKIFY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+="


@dataclass(frozen=True)
class CloakifyResult:
    operation: str
    input_path: str
    output_path: str
    output_paths: list[str]
    cipher_path: str
    alphabet_size: int
    cipher_entries: int
    payload_bytes: int = 0
    base64_chars: int = 0
    cloaked_lines: int = 0
    known_lines: int = 0
    unknown_lines: int = 0
    written_bytes: int = 0
    preview: list[str] | None = None
    count: int = 1

    def to_dict(self) -> dict[str, object]:
        return {"status": "success", **asdict(self)}


def cloakify_file(input_path: Path, cipher_path: Path, output_path: Path) -> CloakifyResult:
    """Encode any payload as a Cloakify list using a custom cipher file."""

    _check_file(input_path, "载荷文件")
    entries = load_cipher(cipher_path)
    payload = input_path.read_bytes()
    encoded = base64.b64encode(payload).decode("ascii")
    table = {char: entries[index] for index, char in enumerate(CLOAKIFY_ALPHABET)}
    lines = [table[char] for char in encoded]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return CloakifyResult(
        operation="text.cloakify.cloak",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        cipher_path=str(cipher_path),
        alphabet_size=len(CLOAKIFY_ALPHABET),
        cipher_entries=len(entries),
        payload_bytes=len(payload),
        base64_chars=len(encoded),
        cloaked_lines=len(lines),
        written_bytes=output_path.stat().st_size,
        preview=lines[:5],
    )


def decloakify_file(
    input_path: Path,
    cipher_path: Path,
    output_path: Path,
    *,
    ignore_unknown: bool = False,
) -> CloakifyResult:
    """Decode a Cloakify list back to its original payload."""

    _check_file(input_path, "Cloakify 文本")
    entries = load_cipher(cipher_path)
    reverse = {entry: CLOAKIFY_ALPHABET[index] for index, entry in enumerate(entries)}
    tokens = _read_cloaked_tokens(input_path)
    clear64: list[str] = []
    unknown: list[str] = []
    for token in tokens:
        if token in reverse:
            clear64.append(reverse[token])
        elif token or not ignore_unknown:
            unknown.append(token)
    if unknown and not ignore_unknown:
        sample = ", ".join(repr(value) for value in unknown[:3])
        raise ValueError(f"Cloakify 字典中找不到 {len(unknown)} 行密文，例如：{sample}")
    try:
        payload = base64.b64decode("".join(clear64), validate=True)
    except ValueError as error:
        raise ValueError(f"Cloakify Base64 解码失败：{error}") from error
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return CloakifyResult(
        operation="text.cloakify.decloak",
        input_path=str(input_path),
        output_path=str(output_path),
        output_paths=[str(output_path)],
        cipher_path=str(cipher_path),
        alphabet_size=len(CLOAKIFY_ALPHABET),
        cipher_entries=len(entries),
        payload_bytes=len(payload),
        base64_chars=len(clear64),
        cloaked_lines=len(tokens),
        known_lines=len(clear64),
        unknown_lines=len(unknown),
        written_bytes=output_path.stat().st_size,
        preview=tokens[:5],
    )


def inspect_cloakify(input_path: Path, cipher_path: Path | None = None) -> CloakifyResult:
    _check_file(input_path, "Cloakify 文本")
    tokens = _read_cloaked_tokens(input_path)
    known = 0
    unknown = 0
    entries: list[str] = []
    cipher_label = "-"
    if cipher_path is not None:
        entries = load_cipher(cipher_path)
        allowed = set(entries[: len(CLOAKIFY_ALPHABET)])
        known = sum(1 for token in tokens if token in allowed)
        unknown = len(tokens) - known
        cipher_label = str(cipher_path)
    return CloakifyResult(
        operation="text.cloakify.inspect",
        input_path=str(input_path),
        output_path="-",
        output_paths=[],
        cipher_path=cipher_label,
        alphabet_size=len(CLOAKIFY_ALPHABET),
        cipher_entries=len(entries),
        cloaked_lines=len(tokens),
        known_lines=known,
        unknown_lines=unknown,
        preview=tokens[:5],
    )


def load_cipher(cipher_path: Path) -> list[str]:
    _check_file(cipher_path, "Cloakify 字典")
    entries = [
        line.rstrip("\r\n") for line in cipher_path.read_text(encoding="utf-8-sig").splitlines()
    ]
    entries = [entry for entry in entries if entry]
    if len(entries) < len(CLOAKIFY_ALPHABET):
        raise ValueError(
            f"Cloakify 字典至少需要 {len(CLOAKIFY_ALPHABET)} 个非空唯一条目，当前 {len(entries)} 个"
        )
    used = entries[: len(CLOAKIFY_ALPHABET)]
    duplicates = sorted({entry for entry in used if used.count(entry) > 1})
    if duplicates:
        raise ValueError(f"Cloakify 字典前 {len(CLOAKIFY_ALPHABET)} 项存在重复：{duplicates[:3]}")
    return used


def _read_cloaked_tokens(input_path: Path) -> list[str]:
    return [
        line.rstrip("\r\n")
        for line in input_path.read_text(encoding="utf-8-sig").splitlines()
        if line.rstrip("\r\n")
    ]


def _check_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label}不存在：{path}")
