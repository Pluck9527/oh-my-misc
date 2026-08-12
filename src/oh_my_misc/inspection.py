from __future__ import annotations

import hashlib
from pathlib import Path

from oh_my_misc.core.result import Finding, InspectionResult
from oh_my_misc.formats.signatures import detect_signature, dimensions

_HEADER_LIMIT = 1024 * 1024


def inspect_file(input_path: str | Path) -> InspectionResult:
    path = Path(input_path).expanduser().resolve()
    if not path.exists():
        return InspectionResult(
            status="failed",
            input_path=str(path),
            errors=({"code": "not_found", "message": "输入文件不存在"},),
        )
    if not path.is_file():
        return InspectionResult(
            status="failed",
            input_path=str(path),
            errors=({"code": "not_file", "message": "输入路径不是普通文件"},),
        )

    digest = hashlib.sha256()
    header = bytearray()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            if len(header) < _HEADER_LIMIT:
                header.extend(chunk[: _HEADER_LIMIT - len(header)])

    signature = detect_signature(bytes(header))
    summary: dict[str, object] = {
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "extension": path.suffix.lower(),
        "kind": signature.kind if signature else "unknown",
        "media_type": signature.media_type if signature else "application/octet-stream",
    }
    findings: list[Finding] = []
    if signature:
        findings.append(Finding("signature", "识别到文件签名", signature.evidence))
        image_dimensions = dimensions(signature.kind, bytes(header))
        if image_dimensions:
            summary["width"], summary["height"] = image_dimensions
        if path.suffix.lower() and path.suffix.lower() not in signature.extensions:
            findings.append(
                Finding(
                    "extension_mismatch",
                    "扩展名与文件签名不一致",
                    f"扩展名 {path.suffix.lower()}，签名类型 {signature.kind}",
                    "warning",
                )
            )
    if not signature:
        findings.append(Finding("unknown_signature", "未识别文件签名", "需要进一步结构分析", "notice"))

    return InspectionResult(
        status="success",
        input_path=str(path),
        summary=summary,
        findings=tuple(findings),
    )
