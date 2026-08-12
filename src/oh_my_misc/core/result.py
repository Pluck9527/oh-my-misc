from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Status = Literal["success", "empty", "unsupported", "failed"]


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    evidence: str
    severity: Literal["info", "notice", "warning"] = "info"


@dataclass(frozen=True)
class InspectionResult:
    status: Status
    input_path: str
    summary: dict[str, object] = field(default_factory=dict)
    findings: tuple[Finding, ...] = ()
    artifacts: tuple[dict[str, object], ...] = ()
    errors: tuple[dict[str, str], ...] = ()
    schema_version: int = 1
    operation: str = "inspect"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "operation": self.operation,
            "input": {"path": self.input_path},
            "summary": self.summary,
            "findings": [asdict(finding) for finding in self.findings],
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
        }
