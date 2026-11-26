"""Cron misconfiguration checks - writable scripts and directories referenced by cron."""

from __future__ import annotations

import os
import re

from ..findings import CheckResult
from ..util import is_writable, read_text

CRON_FILES = ["/etc/crontab"]
CRON_DIRS = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"]


def check(ctx) -> CheckResult:
    result = CheckResult(name="cron")
    uid, gids = ctx.uid, ctx.gids

    entries = []
    for path in CRON_FILES:
        text = read_text(path)
        if text:
            entries.extend(_parse_crontab(text, path))
        if os.path.exists(path) and is_writable(path, uid, gids):
            result.add("critical", f"writable {path}", exploit="add a root cron job, wait for execution")
    for directory in CRON_DIRS:
        if not os.path.isdir(directory):
            continue
        if is_writable(directory, uid, gids):
            result.add("critical", f"writable cron directory {directory}", exploit="drop a script - root cron will run it")
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            full = os.path.join(directory, name)
            text = read_text(full)
            if text and directory == "/etc/cron.d":
                entries.extend(_parse_crontab(text, full))
            elif text:
                _check_script(result, full, uid, gids)

    for entry in entries:
        if entry["user"] != "root":
            continue
        target = entry["command"].split()[0] if entry["command"] else ""
        if not target.startswith("/"):
            continue
        if is_writable(target, uid, gids):
            result.add(
                "critical",
                f"root cron job runs a writable script: {target}",
                detail=f"schedule: {entry['schedule']} in {entry['source']}",
                exploit="append a reverse shell to the script and wait",
            )
        parent = os.path.dirname(target)
        if parent and os.path.isdir(parent) and is_writable(parent, uid, gids):
            result.add(
                "high",
                f"root cron script lives in a writable directory: {parent}",
                detail=target,
                exploit="replace the script in place",
            )

    if not result.findings:
        result.add("info", "no writable cron paths found")
    return result


def _parse_crontab(text: str, source: str) -> list[dict]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0].startswith("@"):
            if len(fields) < 3:
                continue
            schedule, user, command = fields[0], fields[1], " ".join(fields[2:])
        else:
            if len(fields) < 7:
                continue
            schedule, user, command = " ".join(fields[:5]), fields[5], " ".join(fields[6:])
        if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", user):
            entries.append({"schedule": schedule, "user": user, "command": command, "source": source})
    return entries


def _check_script(result: CheckResult, path: str, uid: int, gids: list[int]) -> None:
    if is_writable(path, uid, gids):
        result.add(
            "critical",
            f"writable cron script: {path}",
            exploit="script runs as root on schedule - append your payload",
        )
