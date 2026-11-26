"""Shared helpers: command execution, file access, version parsing."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess

_CMD_TIMEOUT = 8


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(argv: list[str], timeout: int = _CMD_TIMEOUT) -> tuple[int, str]:
    """Run a command, return (exit code, combined output). Never raises."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def read_text(path: str, limit: int = 1 << 20) -> str | None:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def read_first_line(path: str) -> str:
    text = read_text(path, limit=4096)
    if not text:
        return ""
    return text.splitlines()[0].strip() if text.splitlines() else ""


def is_writable(path: str, uid: int, gids: list[int]) -> bool:
    """Effective writability of a path for the given identity."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    if uid == 0:
        return True
    mode = st.st_mode
    if st.st_uid == uid:
        return bool(mode & stat.S_IWUSR)
    if st.st_gid in gids:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


def parse_version(text: str) -> tuple[int, ...]:
    """Turn '1.9.15p5' into (1, 9, 15, 5). Trailing pN maps to a patch level."""
    match = re.search(r"(\d+(?:\.\d+)*)(?:p(\d+))?", text)
    if not match:
        return ()
    parts = [int(p) for p in match.group(1).split(".")]
    if match.group(2):
        parts.append(int(match.group(2)))
    return tuple(parts)


def version_lt(version: tuple[int, ...], other: tuple[int, ...]) -> bool:
    """Compare version tuples, padding the shorter one with zeros."""
    width = max(len(version), len(other))
    padded = version + (0,) * (width - len(version))
    target = other + (0,) * (width - len(other))
    return padded < target


def version_in_range(version: tuple[int, ...], low: tuple[int, ...], high: tuple[int, ...]) -> bool:
    return not version_lt(version, low) and version_lt(version, high)


def kernel_release() -> tuple[int, ...]:
    """Numeric kernel release, distro suffixes stripped: '5.15.0-91-generic' -> (5, 15, 0)."""
    release = os.uname().release
    match = re.match(r"(\d+(?:\.\d+)*)", release)
    if not match:
        return ()
    return tuple(int(p) for p in match.group(1).split("."))


def walking_files(root: str, max_depth: int = 6):
    """Yield file paths under root without following symlinked directories."""
    root = root.rstrip("/")
    base_depth = root.count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.count("/") - base_depth
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            yield os.path.join(dirpath, name)
