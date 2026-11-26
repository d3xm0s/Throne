"""UI strings - English and Russian."""

from __future__ import annotations

STRINGS = {
    "en": {
        "tagline": "linux privilege escalation enumerator",
        "summary": "summary",
        "findings_in": "{total} findings in {elapsed:.1f}s",
        "clean": "clean",
        "root_warning": "warning: running as root - results reflect what root sees, not what an attacker could abuse",
        "unknown_checks": "unknown checks: {names}",
        "available": "available",
        "json_written": "json written to {path} ({elapsed:.1f}s scan)",
        "check_names": {
            "system": "system", "suid": "suid", "capabilities": "capabilities",
            "sudo": "sudo", "cron": "cron", "filesystem": "filesystem",
            "nfs": "nfs", "services": "services", "creds": "creds",
            "procs": "procs", "network": "network", "containers": "containers", "ssh": "ssh",
        },
    },
    "ru": {
        "tagline": "поиск путей повышения привилегий в Linux",
        "summary": "итог",
        "findings_in": "находок: {total} за {elapsed:.1f}с",
        "clean": "чисто",
        "root_warning": "внимание: запуск от root - результаты показывают вид root, а не то, что может абьюзить атакующий",
        "unknown_checks": "неизвестные проверки: {names}",
        "available": "доступные",
        "json_written": "json записан в {path} (сканирование {elapsed:.1f}с)",
        "check_names": {
            "system": "система", "suid": "suid", "capabilities": "capabilities",
            "sudo": "sudo", "cron": "cron", "filesystem": "файлы",
            "nfs": "nfs", "services": "сервисы", "creds": "креды",
            "procs": "процессы", "network": "сеть", "containers": "контейнеры", "ssh": "ssh",
        },
    },
}


def get(lang: str) -> dict:
    return STRINGS.get(lang, STRINGS["en"])
