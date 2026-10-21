"""Scope enforcement: the single gate every target must pass through.

Components ask the ScopeGuard whether a target is permitted before acting.
The guard fails closed: anything not explicitly in scope is denied. Targets may
be a domain, a single IP, or a CIDR network that is a subset of an authorized
range.
"""

from __future__ import annotations

import ipaddress

from .config import Scope


class ScopeError(RuntimeError):
    """Raised when an action is attempted against an out-of-scope target."""


class ScopeGuard:
    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    def is_in_scope(self, target: str) -> bool:
        """True only if target is explicitly authorized and not excluded."""
        if target in self._scope.excluded:
            return False
        if target in self._scope.domains:
            return True
        return self._ip_in_ranges(target)

    def require(self, target: str) -> None:
        """Raise ScopeError unless the target is in scope."""
        if not self.is_in_scope(target):
            raise ScopeError(f"Target {target!r} is not in the authorized scope.")

    def _authorized_networks(self) -> list[ipaddress._BaseNetwork]:
        nets = []
        for cidr in self._scope.ip_ranges:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        return nets

    def _ip_in_ranges(self, target: str) -> bool:
        networks = self._authorized_networks()
        # A single IP address: must fall inside an authorized network.
        try:
            addr = ipaddress.ip_address(target)
            return any(addr in net for net in networks)
        except ValueError:
            pass
        # A CIDR network: must be a subset of an authorized network.
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        for authorized in networks:
            try:
                if net.version == authorized.version and net.subnet_of(authorized):
                    return True
            except (ValueError, TypeError):
                continue
        return False
