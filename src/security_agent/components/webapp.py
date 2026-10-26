"""Web application and API testing (ZAP, mitmproxy, Playwright, manual methodology)."""

from __future__ import annotations

from .base import Component, Finding


class WebAppComponent(Component):
    phase = "webapp"

    def run(self, targets: list[str]) -> list[Finding]:
        # Targets arrive already scope-checked by the orchestrator. Anything this
        # phase derives itself (e.g. discovered hosts) must go through
        # self.scope.require before it is touched.
        # TODO: implement the webapp phase per docs/SECURITY-TESTING-ARCHITECTURE.md.
        raise NotImplementedError("WebApp phase is not implemented yet.")
