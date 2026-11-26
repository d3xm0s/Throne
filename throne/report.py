"""Report rendering: colored terminal output and JSON export."""

from __future__ import annotations

import getpass
import json
import os
import socket
import sys
from dataclasses import asdict

from .findings import CheckResult, SEVERITIES

_COLORS = {
    "info": "\033[36m",
    "low": "\033[34m",
    "medium": "\033[33m",
    "high": "\033[31m",
    "critical": "\033[35;1m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_MAGENTA = "\033[35;1m"

BANNER = r"""
████████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗███████╗
╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝
   ██║   ███████║██████╔╝██║   ██║██╔██╗ ██║█████╗
   ██║   ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╔╝██║ ╚████║███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝"""


class Reporter:
    def __init__(self, color: bool = True, min_severity: str = "info", lang: str = "en", stream=None):
        self.color = color and (stream or sys.stdout).isatty()
        self.min_severity = min_severity
        self.stream = stream or sys.stdout
        from .i18n import get

        self.t = get(lang)

    def banner(self, version: str) -> None:
        if self.color:
            self._line(f"{_MAGENTA}{BANNER}{_RESET}")
        else:
            self._line(BANNER)
        host = socket.gethostname()
        user = getpass.getuser()
        kernel = os.uname().release
        self._line(self._dim(f"  {self.t['tagline']} v{version}"))
        self._line(self._dim(f"  {user}@{host} - kernel {kernel}"))
        self._line("")

    def render(self, results: list[CheckResult]) -> None:
        for result in results:
            visible = [f for f in result.findings if self._shown(f.severity)]
            if not visible:
                continue
            self._section(self.t["check_names"].get(result.name, result.name))
            for i, finding in enumerate(visible):
                last = i == len(visible) - 1
                self._finding(finding, last)
            self._line("")

    def summary(self, results: list[CheckResult], elapsed: float) -> None:
        counts = {sev: 0 for sev in SEVERITIES}
        for result in results:
            for finding in result.findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        total = sum(counts.values())
        info = self.t["findings_in"].format(total=total, elapsed=elapsed)
        self._line(f"{_BOLD}{self.t['summary']}{_RESET} {self._dim(f'({info})')}" if self.color else f"{self.t['summary']} ({info})")
        line = []
        for sev in ("critical", "high", "medium", "low", "info"):
            n = counts[sev]
            if not n:
                continue
            label = f"{sev} {n}"
            line.append(f"{_COLORS[sev]}{label}{_RESET}" if self.color else label)
        self._line("  " + "  ".join(line) if line else "  " + self.t["clean"])
        self._line("")

    def to_json(self, results: list[CheckResult]) -> str:
        payload = {
            "results": [
                {
                    "check": r.name,
                    "errors": r.errors,
                    "findings": [asdict(f) for f in r.findings],
                }
                for r in results
            ]
        }
        return json.dumps(payload, indent=2)

    def _section(self, name: str) -> None:
        if self.color:
            self._line(f"{_MAGENTA}{_BOLD}==[{_RESET} {_BOLD}{name}{_RESET} {_MAGENTA}]{'=' * max(2, 60 - len(name))}{_RESET}")
        else:
            self._line(f"==[ {name} ]{'=' * max(2, 60 - len(name))}")

    def _finding(self, finding, last: bool) -> None:
        branch = "└─" if last else "├─"
        stem = "   " if last else "│  "
        self._line(f"  {branch} {self._tag(finding.severity)} {finding.title}")
        if finding.detail:
            self._line(f"  {stem}{self._dim(finding.detail)}")
        if finding.exploit:
            hint = f"-> {finding.exploit}"
            self._line(f"  {stem}{self._tint(finding.severity, hint)}")

    def _tag(self, severity: str) -> str:
        label = f"[{severity.upper():>8}]"
        if self.color:
            return f"{_COLORS.get(severity, '')}{label}{_RESET}"
        return label

    def _tint(self, severity: str, text: str) -> str:
        if self.color:
            return f"{_COLORS.get(severity, '')}{_DIM}{text}{_RESET}"
        return text

    def _dim(self, text: str) -> str:
        if self.color:
            return f"{_DIM}{text}{_RESET}"
        return text

    def _shown(self, severity: str) -> bool:
        return SEVERITIES.index(severity) >= SEVERITIES.index(self.min_severity)

    def _line(self, text: str) -> None:
        print(text, file=self.stream)
