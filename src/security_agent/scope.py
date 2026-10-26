"""Scope enforcement: the single gate every target must pass through.

Components ask the ScopeGuard whether a target is permitted before acting.
The guard fails closed: anything not explicitly in scope is denied. Targets may
be a domain, a single IP, or a CIDR network that is a subset of an authorized
range.

Exclusions override everything. An excluded domain, IP, or CIDR is never in
scope. A CIDR target that merely *contains* excluded addresses is still in
scope, but whoever acts on it must skip those addresses: ``require`` returns
them so the caller can pass them on (e.g. as ``nmap --exclude``).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from datetime import datetime

from .config import Scope, is_hostname, normalize_domain, parse_network, parse_time_window

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], list[str]]


class ScopeError(RuntimeError):
    """Raised when an action is attempted against an out-of-scope target."""


def resolve_host(name: str) -> list[str]:
    """Return the distinct addresses a hostname resolves to."""
    infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def _overlaps(a: _Network, b: _Network) -> bool:
    return a.version == b.version and a.overlaps(b)


class ScopeGuard:
    def __init__(self, scope: Scope) -> None:
        self._scope = scope
        self._domains = {normalize_domain(d) for d in scope.domains}
        self._networks = [n for n in map(parse_network, scope.ip_ranges) if n is not None]
        self._excluded_networks: list[_Network] = []
        self._excluded_domains: set[str] = set()
        for entry in scope.excluded:
            net = parse_network(entry)
            if net is not None:
                self._excluded_networks.append(net)
            else:
                self._excluded_domains.add(normalize_domain(entry))

    def targets(self) -> list[str]:
        """Every authorized target, as the phases should receive them."""
        return list(self._scope.domains) + list(self._scope.ip_ranges)

    def is_in_scope(self, target: str) -> bool:
        """True only if target is explicitly authorized and not excluded."""
        net = parse_network(target)
        if net is None:
            name = normalize_domain(target)
            return name not in self._excluded_domains and name in self._domains
        # Fully covered by an exclusion: nothing left to test.
        if any(net.version == ex.version and net.subnet_of(ex) for ex in self._excluded_networks):
            return False
        return any(net.version == auth.version and net.subnet_of(auth) for auth in self._networks)

    def excluded_within(self, target: str) -> list[str]:
        """Excluded networks that overlap an IP/CIDR target (empty for domains)."""
        net = parse_network(target)
        if net is None:
            return []
        return [str(ex) for ex in self._excluded_networks if _overlaps(net, ex)]

    def require(self, target: str) -> list[str]:
        """Raise ScopeError unless the target is in scope.

        Returns the excluded addresses inside the target, which the caller
        must not touch.
        """
        if not self.is_in_scope(target):
            raise ScopeError(f"Target {target!r} is not in the authorized scope.")
        return self.excluded_within(target)

    # --- Time windows -------------------------------------------------------

    def in_time_window(self, now: datetime | None = None) -> bool:
        """True if there are no windows, or ``now`` falls inside one of them."""
        if not self._scope.time_windows:
            return True
        for window in self._scope.time_windows:
            start, end = parse_time_window(window)
            current = now or datetime.now(start.tzinfo)
            if current.tzinfo is None and start.tzinfo is not None:
                current = current.astimezone()
            elif current.tzinfo is not None and start.tzinfo is None:
                current = current.astimezone().replace(tzinfo=None)
            if start <= current < end:
                return True
        return False

    def require_time_window(self, now: datetime | None = None) -> None:
        if not self.in_time_window(now):
            raise ScopeError(
                "Outside every authorized time window: " + ", ".join(self._scope.time_windows)
            )

    # --- DNS pinning --------------------------------------------------------

    def resolution_problems(self, resolver: Resolver = resolve_host) -> tuple[list[str], list[str]]:
        """Check where in-scope domains resolve.

        Returns ``(blocking, warnings)``. A domain resolving into an excluded
        network blocks the run. When IP ranges are configured, a domain
        resolving outside all of them is a warning, since scanning it would
        reach infrastructure the IP scope does not cover (a CDN or another
        tenant, for example). Resolution failures are warnings.
        """
        blocking: list[str] = []
        warnings: list[str] = []
        for domain in sorted(self._domains):
            if not is_hostname(domain):
                continue
            try:
                addresses = resolver(domain)
            except OSError as exc:
                warnings.append(f"{domain}: could not resolve ({exc}).")
                continue
            for raw in addresses:
                addr = ipaddress.ip_address(raw)
                if any(addr in ex for ex in self._excluded_networks):
                    blocking.append(f"{domain} resolves to {addr}, which is excluded.")
                elif self._networks and not any(addr in n for n in self._networks):
                    warnings.append(
                        f"{domain} resolves to {addr}, outside the authorized IP ranges."
                    )
        return blocking, warnings
