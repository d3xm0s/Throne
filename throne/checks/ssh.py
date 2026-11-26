"""SSH checks: daemon config weaknesses, key files, pivot targets from known_hosts."""

from __future__ import annotations

import os
import pwd
import re

from ..findings import CheckResult
from ..util import is_writable, read_text


def check(ctx) -> CheckResult:
    result = CheckResult(name="ssh")
    _sshd_config(result)
    _key_files(result, ctx)
    _known_hosts(result, ctx)
    return result


def _sshd_config(result: CheckResult) -> None:
    text = read_text("/etc/ssh/sshd_config")
    if not text:
        return
    active = [ln.strip() for ln in text.splitlines()
              if ln.strip() and not ln.strip().startswith("#")]

    def directive(name: str) -> str | None:
        for ln in active:
            if ln.lower().startswith(name.lower() + " ") or ln.lower() == name.lower():
                parts = ln.split(None, 1)
                return parts[1].strip() if len(parts) > 1 else ""
        return None

    root_login = directive("PermitRootLogin")
    if root_login == "yes":
        result.add("high", "sshd PermitRootLogin yes",
                   exploit="any recovered root password/hash gives direct root ssh")
    pass_auth = directive("PasswordAuthentication")
    if pass_auth == "yes":
        result.add("info", "password authentication enabled on sshd")


def _key_files(result: CheckResult, ctx) -> None:
    homes = {"/root"}
    try:
        homes.update(os.path.join("/home", d) for d in os.listdir("/home"))
    except OSError:
        pass

    for home in sorted(homes):
        auth = os.path.join(home, ".ssh", "authorized_keys")
        if os.path.exists(auth):
            if is_writable(auth, ctx.uid, ctx.gids):
                owner = os.path.basename(home)
                sev = "critical" if owner == "root" else "high"
                result.add(
                    sev,
                    f"writable authorized_keys: {auth}",
                    exploit="append your public key - ssh straight in as that user",
                )
        ssh_dir = os.path.join(home, ".ssh")
        if os.path.isdir(ssh_dir) and is_writable(ssh_dir, ctx.uid, ctx.gids) and home == "/root":
            result.add(
                "critical",
                f"root's .ssh directory is writable: {ssh_dir}",
                exploit="drop authorized_keys - direct root ssh",
            )


def _known_hosts(result: CheckResult, ctx) -> None:
    """Known hosts reveal pivot targets; unhashed entries give plain hostnames."""
    homes = {"/root"}
    try:
        homes.update(os.path.join("/home", d) for d in os.listdir("/home"))
    except OSError:
        pass
    try:
        homes.add(os.path.expanduser("~" + pwd.getpwuid(ctx.uid).pw_name))
    except KeyError:
        pass

    targets = set()
    for home in homes:
        path = os.path.join(home, ".ssh", "known_hosts")
        text = read_text(path, limit=1 << 18)
        if not text:
            continue
        for line in text.splitlines():
            if not line or line.startswith("|") or line.startswith("#"):
                continue  # hashed entries do not reveal the hostname
            fields = line.split()
            if not fields:
                continue
            for host in fields[0].split(","):
                if re.fullmatch(r"[\w.\-]+(\[\d+\])?(:\d+)?", host):
                    targets.add(host)
    if targets:
        sample = ", ".join(sorted(targets)[:10])
        result.add(
            "medium",
            f"{len(targets)} pivot targets from known_hosts",
            detail=sample,
            exploit="reuse keys/creds against these hosts",
        )
