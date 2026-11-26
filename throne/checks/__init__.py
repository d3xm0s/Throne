"""Check registry - each module exposes check(ctx) -> CheckResult."""

from __future__ import annotations

from . import caps, containers, creds, cron, filesystem, network, nfs, procs, services, ssh, sudo, suid, system

ALL_CHECKS = {
    "system": system,
    "suid": suid,
    "capabilities": caps,
    "sudo": sudo,
    "cron": cron,
    "filesystem": filesystem,
    "nfs": nfs,
    "services": services,
    "creds": creds,
    "procs": procs,
    "network": network,
    "containers": containers,
    "ssh": ssh,
}
