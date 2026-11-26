"""Network checks: listening sockets and exposed services."""

from __future__ import annotations

from ..findings import CheckResult
from ..util import read_text

# port -> (service, why it matters for privesc/pivoting)
INTERESTING = {
    6379: ("redis", "often unauthenticated - write ssh keys or cron via CONFIG SET dir"),
    27017: ("mongodb", "frequently unauthenticated - dump data, modify users"),
    3306: ("mysql", "try weak/default creds, UDF privesc if root@localhost"),
    5432: ("postgres", "COPY PROGRAM EXECUTION gives RCE as the db user"),
    5984: ("couchdb", "unauthenticated admin party on old versions"),
    11211: ("memcached", "unauthenticated - read cached sessions/creds"),
    2375: ("docker api", "unauthenticated docker API - container escape to root"),
    2376: ("docker api tls", "docker API - check if client certs are required"),
    9200: ("elasticsearch", "often unauthenticated - data theft"),
    873: ("rsync", "anonymous rsync modules may expose the filesystem"),
    2049: ("nfs", "check exports for no_root_squash"),
    5900: ("vnc", "weak vnc passwords are common"),
    445: ("smb", "check shares for writable/exec content"),
    8080: ("http-alt", "local web panel - often admin without auth"),
    9000: ("php-fpm/ops", "check what listens - ops panels are often soft"),
}


def _parse_proc_net(path: str) -> list[tuple[str, int]]:
    text = read_text(path)
    if not text:
        return []
    out = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != "0A":  # 0A = LISTEN
            continue
        host_hex, port_hex = fields[1].rsplit(":", 1)
        port = int(port_hex, 16)
        if len(host_hex) == 8:
            raw = bytes.fromhex(host_hex)
            host = ".".join(str(b) for b in reversed(raw))
        else:
            host = "::" if host_hex == "0" * 32 else host_hex
        out.append((host, port))
    return out


def check(ctx) -> CheckResult:
    result = CheckResult(name="network")
    listeners = _parse_proc_net("/proc/net/tcp") + _parse_proc_net("/proc/net/tcp6")

    exposed = [(h, p) for h, p in listeners if h not in ("127.0.0.1", "::1", "::")]
    local_only = [(h, p) for h, p in listeners if h in ("127.0.0.1", "::1")]

    for host, port in exposed:
        service = INTERESTING.get(port)
        if service:
            result.add(
                "high",
                f"{service[0]} exposed on {host}:{port}",
                exploit=service[1],
            )
    for host, port in local_only:
        service = INTERESTING.get(port)
        if service:
            result.add(
                "medium",
                f"{service[0]} on localhost:{port}",
                exploit="reachable after foothold - " + service[1],
            )

    unique = {(h, p) for h, p in listeners}
    result.add("info", f"{len(unique)} listening sockets ({len(exposed)} exposed)")
    return result
