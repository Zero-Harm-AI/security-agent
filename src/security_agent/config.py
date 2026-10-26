"""Load and validate engagement configuration.

Loading is strict: unknown keys and wrongly typed values raise ``ConfigError``
instead of being guessed at, because a typo in a security policy (``domain:``
for ``domains:``, or ``active_scanning: "no"``, which is a truthy string) must
never silently widen what the agent may do.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, fields
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when the engagement file is malformed or ambiguous."""


# RFC 1123 hostname: dot-separated labels of letters, digits, and inner hyphens.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def normalize_domain(name: str) -> str:
    return name.strip().lower().rstrip(".")


def is_hostname(name: str) -> bool:
    return bool(_HOSTNAME_RE.match(normalize_domain(name)))


def parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse an IP or CIDR into a network, or return None if it is neither."""
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _parse_timestamp(value: str) -> datetime:
    # Python 3.10's fromisoformat does not accept a trailing "Z".
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def parse_time_window(window: str) -> tuple[datetime, datetime]:
    """Parse ``"<start>/<end>"`` (ISO 8601) into a (start, end) pair.

    Raises ConfigError if either side is malformed, if one side has a timezone
    and the other does not, or if the window is empty.
    """
    try:
        start_s, end_s = window.split("/")
        start, end = _parse_timestamp(start_s), _parse_timestamp(end_s)
    except ValueError as exc:
        raise ConfigError(f"Invalid time window {window!r}: expected '<start>/<end>' in ISO 8601") from exc
    if (start.tzinfo is None) != (end.tzinfo is None):
        raise ConfigError(f"Invalid time window {window!r}: mix of timezone-aware and naive times")
    if end <= start:
        raise ConfigError(f"Invalid time window {window!r}: end is not after start")
    return start, end


@dataclass
class Scope:
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    # Empty means no time restriction; otherwise the run must fall in one window.
    time_windows: list[str] = field(default_factory=list)
    rate_limit_rps: int = 5


@dataclass
class Permissions:
    active_scanning: bool = False
    automated_exploitation: bool = False
    destructive_checks: bool = False
    production_testing: bool = False


_REPORTING_KEYS = {"evidence_dir": str, "redact_secrets": bool, "allow_unscanned_report": bool}
_ENGAGEMENT_KEYS = {"name", "authorized_by", "authorization_ref"}
_TOP_LEVEL_KEYS = {"engagement", "scope", "permissions", "reporting", "require_human_approval"}


def _check_keys(section: str, data: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(
            f"Unknown key(s) in {section!r}: {', '.join(map(str, unknown))}. "
            f"Allowed: {', '.join(sorted(allowed))}"
        )


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name!r} must be a mapping")
    return value


def _require_bool(where: str, value: Any) -> bool:
    # isinstance(True, int) is True, so check bool explicitly; strings are rejected.
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false (unquoted), got {value!r}")
    return value


def _require_str_list(where: str, value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings, got {value!r}")
    return list(value)


def _load_scope(data: dict[str, Any]) -> Scope:
    _check_keys("scope", data, {f.name for f in fields(Scope)})
    rate = data.get("rate_limit_rps", 5)
    if isinstance(rate, bool) or not isinstance(rate, int):
        raise ConfigError(f"scope.rate_limit_rps must be an integer, got {rate!r}")
    return Scope(
        domains=_require_str_list("scope.domains", data.get("domains")),
        ip_ranges=_require_str_list("scope.ip_ranges", data.get("ip_ranges")),
        excluded=_require_str_list("scope.excluded", data.get("excluded")),
        time_windows=_require_str_list("scope.time_windows", data.get("time_windows")),
        rate_limit_rps=rate,
    )


def _load_permissions(data: dict[str, Any]) -> Permissions:
    _check_keys("permissions", data, {f.name for f in fields(Permissions)})
    return Permissions(**{k: _require_bool(f"permissions.{k}", v) for k, v in data.items()})


def _load_reporting(data: dict[str, Any]) -> dict[str, Any]:
    _check_keys("reporting", data, set(_REPORTING_KEYS))
    for key, value in data.items():
        if _REPORTING_KEYS[key] is bool:
            _require_bool(f"reporting.{key}", value)
        elif not isinstance(value, str):
            raise ConfigError(f"reporting.{key} must be a string, got {value!r}")
    return dict(data)


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
    def load(cls, path: str | Path) -> EngagementConfig:
        try:
            data = yaml.safe_load(Path(path).read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{path} must contain a mapping at the top level")
        _check_keys("<top level>", data, _TOP_LEVEL_KEYS)

        engagement = _section(data, "engagement")
        _check_keys("engagement", engagement, _ENGAGEMENT_KEYS)
        for key, value in engagement.items():
            if not isinstance(value, str):
                raise ConfigError(f"engagement.{key} must be a string, got {value!r}")

        return cls(
            name=engagement.get("name", ""),
            authorized_by=engagement.get("authorized_by", ""),
            authorization_ref=engagement.get("authorization_ref", ""),
            scope=_load_scope(_section(data, "scope")),
            permissions=_load_permissions(_section(data, "permissions")),
            require_human_approval=_require_bool(
                "require_human_approval", data.get("require_human_approval", True)
            ),
            reporting=_load_reporting(_section(data, "reporting")),
        )

    def validate(self) -> list[str]:
        """Return a list of problems that should block the run. Empty == OK."""
        problems: list[str] = []
        if not self.authorized_by or not self.authorization_ref:
            problems.append("Missing written-authorization reference.")
        if not (self.scope.domains or self.scope.ip_ranges):
            problems.append("Scope is empty; nothing is authorized to test.")
        for domain in self.scope.domains:
            if not is_hostname(domain):
                problems.append(f"scope.domains: {domain!r} is not a valid hostname.")
        for cidr in self.scope.ip_ranges:
            if parse_network(cidr) is None:
                problems.append(f"scope.ip_ranges: {cidr!r} is not a valid IP or CIDR.")
        for entry in self.scope.excluded:
            if parse_network(entry) is None and not is_hostname(entry):
                problems.append(f"scope.excluded: {entry!r} is not a valid hostname, IP, or CIDR.")
        for window in self.scope.time_windows:
            try:
                parse_time_window(window)
            except ConfigError as exc:
                problems.append(f"scope.time_windows: {exc}")
        if self.scope.rate_limit_rps < 1:
            problems.append("scope.rate_limit_rps must be at least 1.")
        return problems
