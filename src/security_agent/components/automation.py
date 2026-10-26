"""Repeatable checks and orchestration (auditable Python, optional CI)."""

from __future__ import annotations

from .base import Component, Finding


class AutomationComponent(Component):
    phase = "automation"

    def run(self, targets: list[str]) -> list[Finding]:
        # Targets arrive already scope-checked by the orchestrator. Anything this
        # phase derives itself (e.g. discovered hosts) must go through
        # self.scope.require before it is touched.
        # TODO: implement the automation phase per docs/SECURITY-TESTING-ARCHITECTURE.md.
        raise NotImplementedError("Automation phase is not implemented yet.")
