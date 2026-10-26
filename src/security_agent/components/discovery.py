"""Asset discovery and mapping.

Implements a conservative Nmap-based discovery pass. Every target is checked
against the ScopeGuard first, and excluded addresses inside a range are passed
to nmap as ``--exclude``. A port scan is active scanning, so it runs only when
the engagement permits ``active_scanning`` or a human approves it.

Nmap writes XML to stdout. The raw XML is saved as an evidence artifact and
parsed into one summary finding plus one ``lead`` per open port, so later
phases can consume structured results. The nmap command is built here so it
can be inspected and tested without executing anything.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from ..approval import ActionRequest
from .base import Component, Finding

_SCAN_TIMEOUT_SECONDS = 300


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    """Return one dict per open port in nmap ``-oX`` output.

    Raises ``ET.ParseError`` if the output is not XML.
    """
    root = ET.fromstring(xml_text)
    ports: list[dict[str, Any]] = []
    for host in root.iter("host"):
        address = next(
            (a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            svc = service.attrib if service is not None else {}
            ports.append({
                "host": address,
                "hostname": hostname,
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol"),
                "service": svc.get("name"),
                "product": svc.get("product"),
                "version": svc.get("version"),
            })
    return ports


class DiscoveryComponent(Component):
    phase = "discovery"

    def build_command(self, target: str, exclude: list[str] | None = None) -> list[str]:
        """Build a conservative nmap command for one target.

        Defaults to a quiet, host-friendly scan. Version detection is added
        only when the engagement explicitly permits active scanning.
        """
        if target.startswith("-"):
            # Config validation rejects these too; never let a target become an option.
            raise ValueError(f"Refusing option-like target {target!r}")
        rate = max(1, int(self.config.scope.rate_limit_rps))
        cmd = [
            "nmap",
            "-Pn",                       # Don't ping; many hosts block it.
            "-T2",                       # Polite timing.
            "--top-ports", "100",
            "--max-rate", str(rate),
            "-oX", "-",                  # Structured XML on stdout.
        ]
        if self.config.permissions.active_scanning:
            cmd += ["-sV", "--version-light"]
        if exclude:
            cmd += ["--exclude", ",".join(exclude)]
        cmd.append(target)
        return cmd

    def run(self, targets: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for target in targets:
            # Fail closed: never touch anything outside the authorized scope.
            exclude = self.scope.require(target)

            cmd = self.build_command(target, exclude)
            request = ActionRequest(
                phase=self.phase,
                target=target,
                description=f"Run discovery scan: {' '.join(cmd)}",
                high_impact=False,
                permitted=self.config.permissions.active_scanning,
            )
            if not self.approval.request(request):
                self.logger.info("discovery: skipped %s (not approved)", target)
                continue

            if shutil.which("nmap") is None:
                self.logger.warning("discovery: nmap not installed; recording inconclusive for %s", target)
                new = [Finding(
                    phase=self.phase, target=target,
                    title="Discovery not run: nmap unavailable",
                    confidence="inconclusive",
                    evidence={"planned_command": cmd},
                )]
            else:
                self.logger.info("discovery: running %s", " ".join(cmd))
                new = self._run_scan(target, cmd)
            for finding in new:
                self.evidence.record(finding)
            findings.extend(new)
        return findings

    def _run_scan(self, target: str, cmd: list[str]) -> list[Finding]:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=_SCAN_TIMEOUT_SECONDS, check=False,
            )
        except subprocess.TimeoutExpired:
            self.logger.error("discovery: scan timed out for %s", target)
            return [Finding(
                phase=self.phase, target=target,
                title="Discovery scan timed out",
                confidence="inconclusive",
                evidence={"command": cmd, "timeout_seconds": _SCAN_TIMEOUT_SECONDS},
            )]
        except OSError as exc:
            self.logger.error("discovery: could not run nmap for %s: %s", target, exc)
            return [Finding(
                phase=self.phase, target=target,
                title="Discovery scan failed to start",
                confidence="inconclusive",
                evidence={"command": cmd, "error": str(exc)},
            )]

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        artifact = self.evidence.save_artifact(f"nmap-{target}-{stamp}.xml", proc.stdout)
        self.logger.info("discovery: nmap exited %s; raw output saved to %s", proc.returncode, artifact)
        summary_evidence: dict[str, Any] = {
            "command": cmd,
            "returncode": proc.returncode,
            "artifact": str(artifact),
            "stderr": proc.stderr[:2000],
        }
        try:
            open_ports = parse_nmap_xml(proc.stdout)
        except ET.ParseError as exc:
            self.logger.error("discovery: could not parse nmap XML for %s: %s", target, exc)
            summary_evidence["parse_error"] = str(exc)
            return [Finding(
                phase=self.phase, target=target,
                title="Discovery scan output could not be parsed",
                confidence="inconclusive",
                evidence=summary_evidence,
            )]

        summary_evidence["open_ports"] = len(open_ports)
        findings = [Finding(
            phase=self.phase, target=target,
            title=f"Discovery scan completed: {len(open_ports)} open port(s)",
            confidence="lead" if proc.returncode == 0 else "inconclusive",
            evidence=summary_evidence,
        )]
        for p in open_ports:
            label = f"{p['host']}:{p['port']}/{p['protocol']}"
            service = " ".join(x for x in (p["service"], p["product"], p["version"]) if x)
            findings.append(Finding(
                phase=self.phase, target=target,
                title=f"Open port {label}" + (f" ({service})" if service else ""),
                confidence="lead",
                evidence=p,
            ))
        return findings
