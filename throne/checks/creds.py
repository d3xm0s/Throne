"""Credential hunting: passwords in configs, environment, mail."""

from __future__ import annotations

import os
import re

from ..findings import CheckResult
from ..util import read_text, walking_files

CRED_PATTERN = re.compile(
    r"(?i)(?<![a-z])(pass(?:word|wd)?|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?(\S{4,})"
)
CONFIG_ROOTS = ("/etc", "/var/www", "/srv", "/opt", "/usr/local/etc")
CONFIG_GLOBS = (".conf", ".cfg", ".ini", ".env", ".yml", ".yaml", ".json", ".php", ".properties", ".cnf")
SKIP_PREFIXES = ("/etc/ssl", "/etc/pki", "/etc/fonts", "/etc/X11", "/etc/alternatives", "/etc/dictionaries-common")


def check(ctx) -> CheckResult:
    result = CheckResult(name="creds")
    hits = 0

    for root in CONFIG_ROOTS:
        if not os.path.isdir(root):
            continue
        for path in walking_files(root, max_depth=4):
            if hits >= 40:
                break
            if path.startswith(SKIP_PREFIXES):
                continue
            if os.path.basename(path) == "nsswitch.conf":
                continue
            if not path.lower().endswith(CONFIG_GLOBS):
                continue
            text = read_text(path, limit=1 << 18)
            if not text:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", ";")):
                    continue
                match = CRED_PATTERN.search(line)
                if not match or _is_placeholder(match.group(2)):
                    continue
                if not os.access(path, os.R_OK):
                    continue
                hits += 1
                result.add(
                    "high",
                    f"credential-looking value in {path}:{lineno}",
                    detail=_redact(line),
                    exploit="try the password for sudo / lateral movement",
                )
                break

    env = read_text("/proc/1/environ") or ""
    for item in env.split("\0"):
        match = CRED_PATTERN.search(item)
        if match and not _is_placeholder(match.group(2)):
            result.add("high", "credential in PID 1 environment", detail=_redact(item))

    _logs(result)

    for mail in ("/var/mail", "/var/spool/mail"):
        if os.path.isdir(mail):
            try:
                readable = [n for n in os.listdir(mail) if os.access(os.path.join(mail, n), os.R_OK)]
            except OSError:
                readable = []
            for name in readable:
                result.add("medium", f"readable mail spool: {os.path.join(mail, name)}", detail="may contain reset links and credentials")

    if hits == 0 and not any(f.severity == "high" for f in result.findings):
        result.add("info", "no obvious credentials in common config locations")
    return result


LOG_ROOTS = ("/var/log",)
LOG_SKIP = {"history.log", "term.log", "dpkg.log", "alternatives.log", "bootstrap.log"}


def _logs(result: CheckResult) -> None:
    """Credential keywords in readable logs - capped and redacted."""
    hits = 0
    for root in LOG_ROOTS:
        if not os.path.isdir(root):
            continue
        for path in walking_files(root, max_depth=2):
            if hits >= 10:
                return
            if not path.endswith((".log", ".log.1", ".txt")):
                continue
            if os.path.basename(path) in LOG_SKIP:
                continue
            if not os.access(path, os.R_OK):
                continue
            text = read_text(path, limit=1 << 18)
            if not text:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                match = CRED_PATTERN.search(line)
                if not match or _is_placeholder(match.group(2)):
                    continue
                # sudo audit lines carry PWD=<working dir> - a path, not a password
                if match.group(1).lower() == "pwd" and match.group(2).startswith("/"):
                    continue
                hits += 1
                result.add(
                    "high",
                    f"credential-looking value in log {path}:{lineno}",
                    detail=_redact(line),
                    exploit="logs often hold setup-time passwords - try them for sudo",
                )
                break


def _is_placeholder(value: str) -> bool:
    lowered = value.strip("'\"").lower()
    return (
        len(lowered) < 4
        or lowered in ("none", "null", "true", "false", "yes", "no", "changeme", "password",
                        "xxx", "redacted", "***", "write", "read", "read-write")
        or set(lowered) <= {"*", "x"}
        or lowered.startswith(("$", "{", "<"))
    )


def _redact(line: str) -> str:
    def mask(match: re.Match) -> str:
        value = match.group(2)
        shown = value[:2] + "***" + value[-1:] if len(value) > 4 else "***"
        return match.group(0).replace(value, shown)

    return CRED_PATTERN.sub(mask, line.strip())[:200]
