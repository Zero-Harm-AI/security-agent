"""Network and infrastructure exposure (one primary scanner, Prowler for cloud)."""

from __future__ import annotations

from .base import Component, Finding


class InfrastructureComponent(Component):
    phase = "infrastructure"

    def run(self, targets: list[str]) -> list[Finding]:
        for target in targets:
            # Fail closed: never touch anything outside the authorized scope.
            self.scope.require(target)
        # TODO: implement the infrastructure phase per ARCHITECTURE.md.
        raise NotImplementedError("Infrastructure phase is not implemented yet.")
