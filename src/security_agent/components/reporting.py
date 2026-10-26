"""Validate, report, and retest; manage evidence.

The reporting phase does not scan. It serializes every finding collected by
earlier phases into a redacted report under the engagement's evidence
directory, separating confirmed findings from leads and inconclusive results.
The orchestrator runs it even when an earlier phase aborts the run.
"""

from __future__ import annotations

from .base import Component, Finding


class ReportingComponent(Component):
    phase = "reporting"

    def run(self, targets: list[str]) -> list[Finding]:
        path = self.evidence.write_report()
        self.logger.info("reporting: wrote %s (%s)", path, self.evidence.counts())
        # Reporting produces no new findings of its own.
        return []
