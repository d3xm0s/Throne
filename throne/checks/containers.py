"""Container and virtualization group checks - docker/lxd membership is instant root."""

from __future__ import annotations

import os
import pwd

from ..findings import CheckResult
from ..util import read_text

GROUP_PRIVESC = {
    "docker": ("critical", "docker run -v /:/mnt --rm -it alpine chroot /mnt sh - full host root"),
    "lxd": ("critical", "lxd/lxc image abuse - mount host fs into a privileged container"),
    "lxc": ("critical", "lxc group - same container escape as lxd"),
    "disk": ("high", "read raw block devices - debugfs /dev/sda1 to grab /etc/shadow"),
    "adm": ("medium", "read /var/log - creds leak through logs constantly"),
    "sudo": ("high", "in sudo group - if you have the password, you are root"),
    "wheel": ("high", "in wheel group - if you have the password, you are root"),
    "shadow": ("high", "can read /etc/shadow - crack hashes offline"),
    "root": ("high", "member of root group - check what root-group-writable files exist"),
    "kvm": ("low", "kvm access - vm image manipulation"),
    "video": ("low", "framebuffer/screen capture possible"),
    "wireshark": ("medium", "dumpcap without root - sniff the wire for creds"),
}


def check(ctx) -> CheckResult:
    result = CheckResult(name="containers")

    try:
        username = pwd.getpwuid(ctx.uid).pw_name
    except KeyError:
        username = str(ctx.uid)

    groups_text = read_text("/etc/group") or ""
    member_of = set()
    primary_gid = None
    try:
        primary_gid = pwd.getpwuid(ctx.uid).pw_gid
    except KeyError:
        pass
    for line in groups_text.splitlines():
        fields = line.split(":")
        if len(fields) < 4:
            continue
        name, gid, members = fields[0], fields[2], fields[3]
        if username in members.split(",") or (primary_gid is not None and gid == str(primary_gid)):
            member_of.add(name)

    for group in sorted(member_of):
        info = GROUP_PRIVESC.get(group)
        if info:
            sev, hint = info
            result.add(sev, f"user '{username}' in group '{group}'", exploit=hint)

    # container escape surface from inside
    if os.path.exists("/.dockerenv"):
        mounts = read_text("/proc/mounts") or ""
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1].startswith("/host"):
                result.add(
                    "critical",
                    f"host filesystem mounted at {fields[1]}",
                    detail=line,
                    exploit="chroot into the mount - you are host root",
                )

    if not any(f.severity in ("critical", "high", "medium") for f in result.findings):
        result.add("info", "no container group memberships or escape surface")
    return result
