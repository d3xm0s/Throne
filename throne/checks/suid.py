"""SUID/SGID binary discovery and GTFOBins matching."""

from __future__ import annotations

import os
import stat

from ..data import GTFOBINS
from ..findings import CheckResult
from ..util import walking_files

SCAN_ROOTS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt", "/snap/bin")

# SUID by default on a sane system - expected, not a finding
STOCK_SUID = {
    "su", "sudo", "mount", "umount", "passwd", "chsh", "chfn", "gpasswd", "newgrp",
    "pkexec", "fusermount", "fusermount3", "newuidmap", "newgidmap", "expiry",
    "chage", "mount.nfs", "mount.cifs", "ping", "traceroute6.iputils", "pppd",
    "nvidia-modprobe", "kismet_cap_linux_wifi", "kismet_cap_linux_bluetooth",
}


def _interesting(path: str) -> tuple[bool, bool]:
    """Return (suid, sgid) for a regular file."""
    try:
        st = os.lstat(path)
    except OSError:
        return False, False
    if not stat.S_ISREG(st.st_mode):
        return False, False
    return bool(st.st_mode & stat.S_ISUID), bool(st.st_mode & stat.S_ISGID)


def check(ctx) -> CheckResult:
    result = CheckResult(name="suid")
    seen = set()
    scanned_roots = set()
    gtfobins_hits = 0

    for root in SCAN_ROOTS:
        if not os.path.isdir(root):
            continue
        real_root = os.path.realpath(root)
        if real_root in scanned_roots:
            continue
        scanned_roots.add(real_root)
        for path in walking_files(root, max_depth=2):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            suid, sgid = _interesting(path)
            if not (suid or sgid):
                continue
            name = os.path.basename(path)
            data = GTFOBINS.get(name)
            if suid and _is_stock(name):
                continue
            if suid and data and "suid" in data:
                gtfobins_hits += 1
                result.add("critical", f"SUID {name} is abusable", detail=path, exploit=data["suid"])
            elif suid:
                result.add("medium", f"non-standard SUID binary: {path}")
            elif sgid and data:
                result.add("low", f"SGID {name} (gtfobins entry exists)", detail=path)

    result.add("info", f"{len(seen)} binaries scanned, stock SUID set skipped")
    return result


def _is_stock(name: str) -> bool:
    return name in STOCK_SUID or name.startswith("kismet_cap_")
