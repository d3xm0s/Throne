"""Scan context: identity and options shared by all checks."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Context:
    uid: int = field(default_factory=os.geteuid)
    gids: list[int] = field(default_factory=os.getgroups)

    def __post_init__(self) -> None:
        if self.uid not in (0,) and os.getegid() not in self.gids:
            self.gids.append(os.getegid())

    @property
    def is_root(self) -> bool:
        return self.uid == 0
