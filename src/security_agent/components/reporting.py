"""Validate, report, and retest; manage evidence.

The reporting phase does not scan. It serializes every finding collected by
earlier phases into a redacted report under the engagement's evidence
directory, separating confirmed findings from leads and inconclusive results.
"""

from __future__ import annotations

from .base import Component, Finding


class ReportingComponent(Component):
    phase = "reporting"

    def run(self, targets: list[str]) -> list[Finding]:
        path = self.evidence.write_report()
        counts = {"confirmed": 0, "lead": 0, "inconclusive": 0}
        for f in self.evidence.findings:
            counts[getattr(f, "confidence", "lead")] = counts.get(
                getattr(f, "confidence", "lead"), 0
            ) + 1
        self.logger.info("reporting: wrote %s (%s)", path, counts)
        # Reporting produces no new findings of its own.
        return []
