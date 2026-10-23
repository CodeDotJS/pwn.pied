from __future__ import annotations

from dataclasses import asdict, dataclass, field


SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "ok": 5,
}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    location: str
    evidence: str
    remediation: str
    advisory: str = ""
    cves: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Target:
    name: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "files_scanned": self.files_scanned,
            "error": self.error,
            "findings": [finding.to_dict() for finding in self.findings],
        }
