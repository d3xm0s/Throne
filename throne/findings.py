"""Finding model and severity ordering."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")

_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str = ""
    exploit: str = ""

    def rank(self) -> int:
        return _RANK.get(self.severity, 0)


@dataclass
class CheckResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, severity: str, title: str, detail: str = "", exploit: str = "") -> None:
        self.findings.append(
            Finding(check=self.name, severity=severity, title=title, detail=detail, exploit=exploit)
        )


def meets_threshold(severity: str, threshold: str) -> bool:
    return _RANK.get(severity, 0) >= _RANK.get(threshold, 0)
