"""Filesystem checks: writable sensitive files, SSH keys, interesting home content."""

from __future__ import annotations

import os
import stat

from ..data import SENSITIVE_FILES
from ..findings import CheckResult
from ..util import is_writable, read_text, walking_files

HOME_CLUTTER = (".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/authorized_keys",
                ".bash_history", ".zsh_history", ".mysql_history", ".psql_history",
                ".aws/credentials", ".config/gcloud", ".git-credentials", ".netrc")


def check(ctx) -> CheckResult:
    result = CheckResult(name="filesystem")
    uid, gids = ctx.uid, ctx.gids

    for path in SENSITIVE_FILES:
        if not os.path.exists(path):
            continue
        if is_writable(path, uid, gids):
            result.add("critical", f"writable sensitive file: {path}", exploit="inject a root user or modify auth config")

    # these are root-readable only on a sane system - readable copies mean misconfig
    for path in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers"):
        if os.path.exists(path) and os.access(path, os.R_OK) and uid != 0:
            result.add("high", f"readable sensitive file: {path}", detail="normally root-only", exploit="crack hashes offline: john / hashcat")

    _home_dirs(result, ctx)
    _tmp_world_writable(result)
    _shadow_backups(result)
    _private_keys(result, ctx)
    _root_dotfiles(result, ctx)
    _writable_etc(result, ctx)
    return result


def _writable_etc(result: CheckResult, ctx) -> None:
    """Any root-owned file under /etc writable by us is a config takeover."""
    count = 0
    for path in walking_files("/etc", max_depth=3):
        if count >= 15:
            return
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            continue
        if is_writable(path, ctx.uid, ctx.gids):
            count += 1
            result.add(
                "high",
                f"root-owned but writable: {path}",
                exploit="edit the config - influence whatever root process reads it",
            )


def _private_keys(result: CheckResult, ctx) -> None:
    """Hunt private keys and vpn profiles in common locations."""
    count = 0
    for root in ("/home", "/root", "/etc", "/opt", "/srv"):
        if not os.path.isdir(root):
            continue
        for path in walking_files(root, max_depth=5):
            if count >= 25:
                return
            name = os.path.basename(path).lower()
            if not name.endswith((".pem", ".key", ".ovpn", ".ppk")) and name not in ("id_rsa", "id_dsa", "id_ed25519", "id_ecdsa"):
                continue
            if name.endswith((".pub", ".crt", "-cert.pem")):
                continue
            if not os.access(path, os.R_OK):
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_uid == ctx.uid and "home" in path:
                continue  # own keys are not a finding
            head = read_text(path, limit=8192) or ""
            if name.endswith((".pem", ".key")) and "PRIVATE KEY-----" not in head:
                continue  # public certs and bundles are everywhere
            count += 1
            result.add(
                "high",
                f"readable private key: {path}",
                exploit="reuse for ssh/vpn - often passwordless and tied to other hosts",
            )


def _root_dotfiles(result: CheckResult, ctx) -> None:
    """Writable root-owned dotfiles - payload runs at root login."""
    for name in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
        path = os.path.join("/root", name)
        if os.path.exists(path) and is_writable(path, ctx.uid, ctx.gids):
            result.add(
                "critical",
                f"writable root dotfile: {path}",
                exploit="append a payload - it fires at next root login/shell",
            )


def _home_dirs(result: CheckResult, ctx) -> None:
    homes = {"/root"}
    try:
        homes.update(os.path.join("/home", d) for d in os.listdir("/home"))
    except OSError:
        pass

    for home in sorted(homes):
        if not os.path.isdir(home):
            continue
        for rel in HOME_CLUTTER:
            path = os.path.join(home, rel)
            if not os.path.isfile(path) or not os.access(path, os.R_OK):
                continue
            if rel.endswith(("_history",)):
                _history_hit(result, path, home)
            elif "id_rsa" in rel or "id_ed25519" in rel or "id_ecdsa" in rel:
                if os.stat(path).st_uid == ctx.uid or ctx.uid == 0:
                    continue
                result.add("high", f"readable SSH private key: {path}", exploit="ssh -i <key> user@host")
            elif rel == ".aws/credentials":
                result.add("high", f"readable AWS credentials: {path}")
            elif rel == ".netrc":
                result.add("medium", f"readable .netrc: {path}", detail="may contain plaintext logins")
            elif rel == ".git-credentials":
                result.add("high", f"readable .git-credentials: {path}", detail="plaintext git passwords")


def _history_hit(result: CheckResult, path: str, home: str) -> None:
    text = read_text(path, limit=1 << 18) or ""
    if not text.strip():
        return
    owner = os.path.basename(home)
    keywords = ("passw", "secret", "token", "apikey", "api_key", "mysql", "psql", "sshpass", "export AWS")
    hits = [ln for ln in text.splitlines() if any(k in ln.lower() for k in keywords)]
    if hits:
        result.add(
            "medium",
            f"{path}: {len(hits)} lines with credential-looking keywords",
            detail=f"owner: {owner} - review the history for reused passwords",
        )


def _tmp_world_writable(result: CheckResult) -> None:
    for path in ("/tmp", "/var/tmp", "/dev/shm"):
        try:
            mode = os.stat(path).st_mode
        except OSError:
            continue
        if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
            result.add(
                "high",
                f"{path} world-writable without sticky bit",
                exploit="plant files for root cron/suid consumers to pick up",
            )


def _shadow_backups(result: CheckResult) -> None:
    candidates = []
    for root in ("/etc", "/var/backups", "/root", "/home"):
        if not os.path.isdir(root):
            continue
        for path in walking_files(root, max_depth=3):
            name = os.path.basename(path).lower()
            if name.startswith(("shadow", "gshadow", "sudoers")) and name not in ("shadow", "gshadow", "sudoers"):
                candidates.append(path)
    for path in candidates[:50]:
        if os.access(path, os.R_OK):
            result.add("high", f"readable credential backup: {path}", exploit="crack hashes offline: john / hashcat")
