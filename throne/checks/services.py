"""Service checks: root processes with writable binaries/paths, writable systemd units, PATH hijack."""

from __future__ import annotations

import os
import re
import stat

from ..findings import CheckResult
from ..util import is_writable, read_text, walking_files

SYSTEMD_DIRS = ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system")


def check(ctx) -> CheckResult:
    result = CheckResult(name="services")
    _root_processes(result, ctx)
    _systemd_units(result, ctx)
    _path_hijack(result, ctx)
    _sessions(result, ctx)
    return result


def _sessions(result: CheckResult, ctx) -> None:
    """Detached screen/tmux sessions owned by root - attach and you are root."""
    for base, kind in (("/run/screen", "screen"), ("/tmp", "tmux")):
        try:
            entries = os.listdir(base)
        except OSError:
            continue
        for entry in entries:
            if kind == "screen" and not entry.startswith("S-"):
                continue
            if kind == "tmux" and not entry.startswith("tmux-"):
                continue
            path = os.path.join(base, entry)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_uid != 0:
                continue
            if os.access(path, os.R_OK | os.X_OK) or is_writable(path, ctx.uid, ctx.gids):
                result.add(
                    "critical",
                    f"root {kind} session dir accessible: {path}",
                    exploit=f"{kind} -x root/ or attach via the socket - live root shell",
                )


def _root_processes(result: CheckResult, ctx) -> None:
    seen = set()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return
    for pid in pids:
        try:
            with open(f"/proc/{pid}/status") as fh:
                status = fh.read()
        except OSError:
            continue
        uid_match = re.search(r"^Uid:\s*(\d+)", status, re.M)
        if not uid_match or uid_match.group(1).split()[0] != "0":
            continue
        exe = ""
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
        if exe and exe not in seen and not exe.startswith(("/proc", "/sys")):
            seen.add(exe)
            clean = exe.split(" ")[0].removesuffix(" (deleted)")
            if os.path.exists(clean) and is_writable(clean, ctx.uid, ctx.gids):
                result.add(
                    "critical",
                    f"root process runs a writable binary: {clean}",
                    detail=f"pid {pid}",
                    exploit="overwrite the binary and wait for a restart, or replace via the package manager path",
                )
    if not seen:
        result.add("info", "no root process binaries readable/writable from /proc")


def _systemd_units(result: CheckResult, ctx) -> None:
    scanned_dirs = set()
    for directory in SYSTEMD_DIRS:
        if not os.path.isdir(directory):
            continue
        real_dir = os.path.realpath(directory)
        if real_dir in scanned_dirs:
            continue
        scanned_dirs.add(real_dir)
        if is_writable(directory, ctx.uid, ctx.gids):
            result.add(
                "critical",
                f"writable systemd unit directory: {directory}",
                exploit="write a unit with ExecStart=/bin/sh payload, systemctl enable it",
            )
        for path in walking_files(directory, max_depth=1):
            if not path.endswith((".service", ".timer", ".socket")):
                continue
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                # masked units are symlinks to /dev/null - not attack surface
                continue
            if is_writable(path, ctx.uid, ctx.gids):
                result.add(
                    "critical",
                    f"writable systemd unit: {path}",
                    exploit="edit ExecStart to run your payload as root, systemctl daemon-reload + restart",
                )
                continue
            text = read_text(path) or ""
            exec_match = re.search(r"^ExecStart=(?:-\S*\s+)*(\S+)", text, re.M)
            if exec_match:
                binary = exec_match.group(1)
                if os.path.exists(binary) and is_writable(binary, ctx.uid, ctx.gids):
                    result.add(
                        "critical",
                        f"service {os.path.basename(path)} runs writable binary {binary}",
                        detail=path,
                        exploit="overwrite the binary, restart the service for root",
                    )


def _path_hijack(result: CheckResult, ctx) -> None:
    path_env = os.environ.get("PATH", "")
    for entry in path_env.split(":"):
        if not entry or not os.path.isdir(entry):
            continue
        if entry in (".", ""):
            result.add("high", "current directory in PATH", exploit="plant a fake common binary in a cwd root visits")
            continue
        if is_writable(entry, ctx.uid, ctx.gids) and entry not in ("/tmp",):
            result.add(
                "high",
                f"writable PATH directory: {entry}",
                exploit="drop a fake sudo/ls - anything a root shell might call",
            )
