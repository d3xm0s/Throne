"""System-level checks: kernel CVEs, containers, mitigations."""

from __future__ import annotations

import os
import re

from ..data import KERNEL_CVES
from ..findings import CheckResult
from ..util import kernel_release, parse_version, read_text, run, version_in_range


def check(ctx) -> CheckResult:
    result = CheckResult(name="system")

    release = os.uname().release
    version = kernel_release()
    result.add("info", f"kernel {release}", detail=f"machine: {os.uname().machine}, os: {_os_release()}")

    for name, cve, low, high, hint in KERNEL_CVES:
        if version and version_in_range(version, low, high):
            result.add(
                "high",
                f"kernel {release} in {name} range ({cve})",
                detail=f"vulnerable range: {_fmt(low)} <= v < {_fmt(high)} - distro backports may differ",
                exploit=hint,
            )

    _containers(result)
    _mitigations(result)
    _userns(result)
    _glibc(result)
    return result


def _glibc(result: CheckResult) -> None:
    """Looney Tunables CVE-2023-4911 - glibc 2.35/2.36 shipped by late-2023 distros."""
    code, out = run(["ldd", "--version"])
    match = re.search(r"(\d+\.\d+)", out)
    if not match:
        return
    version = parse_version(match.group(1))
    if version in ((2, 35), (2, 36), (2, 37)):
        result.add(
            "high",
            f"glibc {match.group(1)} may be vulnerable to Looney Tunables (CVE-2023-4911)",
            detail="unpatched 2.35-2.37 builds (Ubuntu 23.04, Fedora 37/38 era)",
            exploit="GLIBC_TUNABLES buffer overflow via SUID binary - public exploits exist",
        )


def _os_release() -> str:
    text = read_text("/etc/os-release") or ""
    match = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', text, re.M)
    return match.group(1) if match else "unknown"


def _fmt(version: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in version)


def _containers(result: CheckResult) -> None:
    markers = []
    if os.path.exists("/.dockerenv"):
        markers.append("/.dockerenv present")
    cgroup = read_text("/proc/1/cgroup") or ""
    if re.search(r"docker|kubepods|containerd", cgroup):
        markers.append("container runtime in /proc/1/cgroup")
    if re.search(r"lxc", cgroup):
        markers.append("lxc in /proc/1/cgroup")
    if markers:
        result.add(
            "medium",
            "running inside a container",
            detail="; ".join(markers),
            exploit="look for mounted docker.sock, CAP_SYS_ADMIN, or shared host paths for a breakout",
        )
    if os.path.exists("/run/docker.sock") or os.path.exists("/var/run/docker.sock"):
        sock = "/var/run/docker.sock" if os.path.exists("/var/run/docker.sock") else "/run/docker.sock"
        result.add(
            "critical",
            "docker.sock accessible",
            detail=sock,
            exploit="docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh",
        )


def _mitigations(result: CheckResult) -> None:
    aslr = read_text("/proc/sys/kernel/randomize_va_space")
    if aslr is not None and aslr.strip() == "0":
        result.add("low", "ASLR disabled", detail="/proc/sys/kernel/randomize_va_space = 0")
    if os.path.exists("/sys/kernel/security/apparmor/profiles"):
        result.add("info", "AppArmor enabled")
    selinux = read_text("/sys/fs/selinux/enforce")
    if selinux is not None and selinux.strip() == "1":
        result.add("info", "SELinux enforcing")


def _userns(result: CheckResult) -> None:
    value = read_text("/proc/sys/kernel/unprivileged_userns_clone")
    if value is not None and value.strip() == "1":
        result.add(
            "medium",
            "unprivileged user namespaces enabled",
            detail="/proc/sys/kernel/unprivileged_userns_clone = 1",
            exploit="many kernel LPE exploits require unprivileged userns (unshare -Urn)",
        )
    max_value = read_text("/proc/sys/user/max_user_namespaces")
    if max_value is not None and max_value.strip() not in ("0", ""):
        result.add("info", f"max_user_namespaces = {max_value.strip()}")
    code, _ = run(["unshare", "-Urn", "true"])
    if code == 0:
        result.add(
            "medium",
            "user namespace creation works",
            detail="unshare -Urn succeeded",
            exploit="kernel exploits abusing userns will run on this host",
        )
