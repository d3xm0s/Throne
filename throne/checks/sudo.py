"""Sudo checks: version CVEs, sudo -l rules, GTFOBins matching."""

from __future__ import annotations

import os
import re

from ..data import GTFOBINS, SUDO_CVES
from ..findings import CheckResult
from ..util import have, parse_version, read_text, run, version_in_range


def check(ctx) -> CheckResult:
    result = CheckResult(name="sudo")

    _version(result)
    _sudo_l(result, ctx)
    _sudoers_files(result)
    _pwnkit(result)
    return result


def _version(result: CheckResult) -> None:
    if not have("sudo"):
        result.add("info", "sudo not installed")
        return
    code, out = run(["sudo", "-V"])
    match = re.search(r"Sudo version (\S+)", out)
    if not match:
        return
    version = parse_version(match.group(1))
    result.add("info", f"sudo {match.group(1)}")
    for name, cve, low, high, hint in SUDO_CVES:
        if version and version_in_range(version, low, high):
            result.add("critical", f"sudo {match.group(1)} vulnerable to {name} ({cve})", exploit=hint)


def _sudo_l(result: CheckResult, ctx) -> None:
    code, out = run(["sudo", "-n", "-l"])
    if code != 0:
        result.add("info", "sudo -l needs a password (non-interactive run failed)")
        return

    nopasswd_rules = _parse_nopasswd(out)
    for binary, runas in nopasswd_rules:
        base = os.path.basename(binary)
        data = GTFOBINS.get(base)
        if data and "sudo" in data:
            result.add(
                "critical",
                f"NOPASSWD sudo rule on abusable binary: {binary}",
                detail=f"run as: {runas}",
                exploit=data["sudo"],
            )
        elif binary == "ALL":
            result.add("critical", f"NOPASSWD: ALL as {runas}", exploit="sudo -u " + runas.strip("()") + " /bin/sh")
        else:
            result.add("high", f"NOPASSWD sudo rule: {binary} as {runas}", detail="check GTFOBins for this binary")

    if "env_keep" in out or "env_reset" not in out and "SETENV" in out:
        result.add(
            "high",
            "sudo keeps environment (SETENV or env_keep)",
            exploit="LD_PRELOAD=/tmp/x.so sudo <allowed_cmd> - shared object executed as root",
        )


def _parse_nopasswd(output: str) -> list[tuple[str, str]]:
    """Extract (command, runas) pairs from NOPASSWD entries in sudo -l output."""
    pairs = []
    for line in output.splitlines():
        if "NOPASSWD" not in line:
            continue
        runas_match = re.search(r"\(([^)]+)\)", line)
        runas = f"({runas_match.group(1)})" if runas_match else "(root)"
        cmd_match = re.search(r"NOPASSWD:\s*(.+)$", line)
        if not cmd_match:
            continue
        for cmd in cmd_match.group(1).split(","):
            binary = cmd.strip().split()[0] if cmd.strip() else ""
            if binary:
                pairs.append((binary, runas))
    return pairs


def _sudoers_files(result: CheckResult) -> None:
    for path in ("/etc/sudoers",):
        if os.access(path, os.R_OK):
            result.add("medium", f"{path} is readable", detail="review rules manually for misconfigurations")
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        try:
            for name in os.listdir(sudoers_d):
                full = os.path.join(sudoers_d, name)
                if os.access(full, os.R_OK):
                    result.add("medium", f"sudoers drop-in readable: {full}")
        except OSError:
            pass


def _pwnkit(result: CheckResult) -> None:
    """CVE-2021-4034 - any pkexec before the January 2022 patch is vulnerable."""
    if not have("pkexec"):
        return
    code, out = run(["pkexec", "--version"])
    match = re.search(r"(\d+\.\d+)", out)
    if not match:
        return
    version = parse_version(match.group(1))
    if version and version < (0, 120):
        result.add(
            "critical",
            f"polkit {match.group(1)} likely vulnerable to PwnKit (CVE-2021-4034)",
            detail="polkit < 0.120 with unpatched pkexec",
            exploit="public PwnKit exploits give instant root on unpatched hosts",
        )
