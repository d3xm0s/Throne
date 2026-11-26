"""Process checks: credential-bearing cmdlines, interesting capabilities, uid map."""

from __future__ import annotations

import os
import re

from ..findings import CheckResult
from ..util import read_text

CRED_ARG = re.compile(r"(?i)(pass(?:word|wd)?|pwd|secret|token)[=: ](\S{3,})")

CAP_NAMES = {
    0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 3: "CAP_FOWNER", 4: "CAP_FSETID",
    5: "CAP_KILL", 6: "CAP_SETGID", 7: "CAP_SETUID", 8: "CAP_SETPCAP",
    17: "CAP_SYS_RAWIO", 21: "CAP_SYS_ADMIN", 24: "CAP_SYS_RESOURCE",
    27: "CAP_SYS_PTRACE", 29: "CAP_AUDIT_WRITE", 31: "CAP_AUDIT_CONTROL",
    34: "CAP_DAC_READ_SEARCH", 38: "CAP_NET_ADMIN",
}
DANGEROUS_CAPS = {"CAP_SETUID", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"}


def _readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


_SELF_USERNS = _readlink("/proc/self/ns/user")


def check(ctx) -> CheckResult:
    result = CheckResult(name="procs")
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        result.errors.append("/proc unreadable")
        return result

    root_count = 0
    for pid in pids:
        status = read_text(f"/proc/{pid}/status", limit=8192)
        if status is None:
            continue
        uid_match = re.search(r"^Uid:\s*(\d+)", status, re.M)
        owner = int(uid_match.group(1)) if uid_match else -1
        if owner == 0:
            root_count += 1

        cmdline = read_text(f"/proc/{pid}/cmdline", limit=8192)
        if cmdline:
            args = cmdline.replace("\0", " ").strip()
            match = CRED_ARG.search(args)
            if match and not _is_noise(args):
                name_match = re.search(r"^Name:\s*(\S+)", status, re.M)
                proc = name_match.group(1) if name_match else pid
                result.add(
                    "high",
                    f"credential in cmdline of {proc} (pid {pid})",
                    detail=_redact(args)[:160],
                    exploit="grab the password, try sudo and lateral movement",
                )

        # effective capabilities of non-root processes - an abusable cap is a shell upgrade
        cap_match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status, re.M)
        if cap_match and owner not in (0, -1):
            # caps held inside a user namespace (sandboxed browsers etc.) are not real
            own_userns = _readlink(f"/proc/{pid}/ns/user")
            if own_userns != _SELF_USERNS:
                continue
            mask = int(cap_match.group(1), 16)
            caps = {name for bit, name in CAP_NAMES.items() if mask & (1 << bit)}
            dangerous = caps & DANGEROUS_CAPS
            if dangerous:
                name_match = re.search(r"^Name:\s*(\S+)", status, re.M)
                proc = name_match.group(1) if name_match else pid
                result.add(
                    "high",
                    f"process {proc} (pid {pid}) holds {', '.join(sorted(dangerous))}",
                    detail=f"runs as uid {owner}",
                    exploit="inject into or ptrace this process to inherit the capability",
                )

    result.add("info", f"{len(pids)} processes, {root_count} running as root")
    return result


def _is_noise(cmdline: str) -> bool:
    lowered = cmdline.lower()
    return any(tag in lowered for tag in ("grep", "throne", "passphrase prompt", "askpass"))


def _redact(text: str) -> str:
    return CRED_ARG.sub(lambda m: m.group(1) + "=***", text)
