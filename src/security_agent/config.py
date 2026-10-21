"""Load and validate engagement configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Scope:
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    time_windows: list[str] = field(default_factory=list)
    rate_limit_rps: int = 5


@dataclass
class Permissions:
    active_scanning: bool = False
    automated_exploitation: bool = False
    destructive_checks: bool = False
    production_testing: bool = False


@dataclass
class EngagementConfig:
    name: str
    authorized_by: str
    authorization_ref: str
    scope: Scope
    permissions: Permissions
    require_human_approval: bool = True
    reporting: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "EngagementConfig":
        data = yaml.safe_load(Path(path).read_text()) or {}
        engagement = data.get("engagement", {})
        return cls(
            name=engagement.get("name", ""),
            authorized_by=engagement.get("authorized_by", ""),
            authorization_ref=engagement.get("authorization_ref", ""),
            scope=Scope(**(data.get("scope") or {})),
            permissions=Permissions(**(data.get("permissions") or {})),
            require_human_approval=data.get("require_human_approval", True),
            reporting=data.get("reporting") or {},
        )

    def validate(self) -> list[str]:
        """Return a list of problems that should block the run. Empty == OK."""
        problems: list[str] = []
        if not self.authorized_by or not self.authorization_ref:
            problems.append("Missing written-authorization reference.")
        if not (self.scope.domains or self.scope.ip_ranges):
            problems.append("Scope is empty; nothing is authorized to test.")
        return problems
