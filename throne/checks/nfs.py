"""NFS export checks - no_root_squash means root on the export for any client."""

from __future__ import annotations

import re

from ..findings import CheckResult
from ..util import read_text


def check(ctx) -> CheckResult:
    result = CheckResult(name="nfs")

    exports = read_text("/etc/exports")
    if exports:
        for line in exports.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "no_root_squash" in line:
                result.add(
                    "critical",
                    f"NFS export with no_root_squash: {line.split()[0]}",
                    detail=line,
                    exploit="mount from your box, drop a SUID /bin/bash, run it on the target",
                )
            elif "no_all_squash" in line:
                result.add("medium", f"NFS export keeps client uids: {line.split()[0]}", detail=line)

    mounts = read_text("/proc/mounts") or ""
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] in ("nfs", "nfs4"):
            result.add("info", f"nfs mount: {fields[0]} -> {fields[1]}")
    return result
