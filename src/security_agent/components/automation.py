"""Repeatable checks and orchestration (auditable Python, optional CI)."""

from __future__ import annotations

from .base import Component, Finding


class AutomationComponent(Component):
    phase = "automation"

    def run(self, targets: list[str]) -> list[Finding]:
        for target in targets:
            # Fail closed: never touch anything outside the authorized scope.
            self.scope.require(target)
        # TODO: implement the automation phase per ARCHITECTURE.md.
        raise NotImplementedError("Automation phase is not implemented yet.")
