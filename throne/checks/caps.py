"""File capability checks - getcap on standard locations."""

from __future__ import annotations

import re

from ..data import CAP_ABUSE
from ..findings import CheckResult
from ..util import have, run


def check(ctx) -> CheckResult:
    result = CheckResult(name="capabilities")
    if not have("getcap"):
        result.errors.append("getcap not installed")
        return result

    code, out = run(["getcap", "-r", "/usr", "/bin", "/sbin", "/opt", "/etc"], timeout=20)
    if code == -1:
        result.errors.append("getcap run failed")
        return result

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^(\S+)\s+(.+)$", line)
        if not match:
            continue
        path, caps = match.group(1), match.group(2)
        dangerous = [cap for cap in CAP_ABUSE if cap in caps]
        if not dangerous:
            result.add("low", f"capabilities on {path}", detail=caps)
            continue
        worst = dangerous[0]
        severity = "critical" if worst in ("cap_setuid", "cap_sys_admin", "cap_sys_module", "cap_dac_override", "cap_setfcap") else "high"
        result.add(
            severity,
            f"{worst} on {path}",
            detail=caps,
            exploit=CAP_ABUSE[worst],
        )
    return result
