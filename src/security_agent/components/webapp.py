"""Web application and API testing (ZAP, mitmproxy, Playwright, manual methodology)."""

from __future__ import annotations

from .base import Component, Finding


class WebAppComponent(Component):
    phase = "webapp"

    def run(self, targets: list[str]) -> list[Finding]:
        for target in targets:
            # Fail closed: never touch anything outside the authorized scope.
            self.scope.require(target)
        # TODO: implement the webapp phase per ARCHITECTURE.md.
        raise NotImplementedError("WebApp phase is not implemented yet.")
