"""Network and infrastructure exposure (one primary scanner, Prowler for cloud)."""

from __future__ import annotations

from .base import Component, Finding


class InfrastructureComponent(Component):
    phase = "infrastructure"

    def run(self, targets: list[str]) -> list[Finding]:
        # Targets arrive already scope-checked by the orchestrator. Anything this
        # phase derives itself (e.g. discovered hosts) must go through
        # self.scope.require before it is touched.
        # TODO: implement the infrastructure phase per docs/SECURITY-TESTING-ARCHITECTURE.md.
        raise NotImplementedError("Infrastructure phase is not implemented yet.")
