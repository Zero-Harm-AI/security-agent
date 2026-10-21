"""Asset discovery and mapping.

Implements a conservative Nmap-based discovery pass. Every target is checked
against the ScopeGuard first, and active scanning is run only when the
engagement permits it or a human approves it. The nmap command is built here so
it can be inspected and tested without executing anything.
"""

from __future__ import annotations

import shutil
import subprocess

from ..approval import ActionRequest
from .base import Component, Finding

_SCAN_TIMEOUT_SECONDS = 300


class DiscoveryComponent(Component):
    phase = "discovery"

    def build_command(self, target: str) -> list[str]:
        """Build a conservative nmap command for one target.

        Defaults to a quiet, host-friendly scan. Version detection is added
        only when the engagement explicitly permits active scanning.
        """
        rate = max(1, int(self.config.scope.rate_limit_rps))
        cmd = [
            "nmap",
            "-Pn",                       # Don't ping; many hosts block it.
            "-T2",                       # Polite timing.
            "--top-ports", "100",
            "--max-rate", str(rate),
        ]
        if self.config.permissions.active_scanning:
            cmd += ["-sV", "--version-light"]
        cmd.append(target)
        return cmd

    def run(self, targets: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for target in targets:
            # Fail closed: never touch anything outside the authorized scope.
            self.scope.require(target)

            cmd = self.build_command(target)
            request = ActionRequest(
                phase=self.phase,
                target=target,
                description=f"Run discovery scan: {' '.join(cmd)}",
                high_impact=False,
            )
            # Active scanning beyond standing permission needs approval.
            if not self.config.permissions.active_scanning:
                if not self.approval.request(request):
                    self.logger.info("discovery: skipped %s (not approved)", target)
                    continue

            if shutil.which("nmap") is None:
                self.logger.warning("discovery: nmap not installed; recording lead for %s", target)
                finding = Finding(
                    phase=self.phase, target=target,
                    title="Discovery not run: nmap unavailable",
                    confidence="inconclusive",
                    evidence={"planned_command": cmd},
                )
                self.evidence.record(finding)
                findings.append(finding)
                continue

            self.logger.info("discovery: running %s", " ".join(cmd))
            finding = self._run_scan(target, cmd)
            self.evidence.record(finding)
            findings.append(finding)
        return findings

    def _run_scan(self, target: str, cmd: list[str]) -> Finding:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=_SCAN_TIMEOUT_SECONDS, check=False,
            )
            return Finding(
                phase=self.phase, target=target,
                title="Discovery scan completed",
                confidence="lead",
                evidence={
                    "command": cmd,
                    "returncode": proc.returncode,
                    "stdout": proc.stdout[-8000:],
                    "stderr": proc.stderr[-2000:],
                },
            )
        except subprocess.TimeoutExpired:
            self.logger.error("discovery: scan timed out for %s", target)
            return Finding(
                phase=self.phase, target=target,
                title="Discovery scan timed out",
                confidence="inconclusive",
                evidence={"command": cmd, "timeout_seconds": _SCAN_TIMEOUT_SECONDS},
            )
