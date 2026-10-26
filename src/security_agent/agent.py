"""Agent entry point.

Loads an engagement config, enforces scope, and runs the workflow phases in
order. Implemented phases run; phases still stubbed are logged and skipped so
the pipeline completes. The orchestrator does nothing unattended: anything
beyond standing permissions goes through the human approval gate, and scope or
time-window violations abort the run. The report is written however the run
ends, so evidence gathered before an abort is never lost.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .approval import ApprovalGate
from .audit import RedactingFilter, build_logger
from .components import (
    AutomationComponent,
    DiscoveryComponent,
    InfrastructureComponent,
    ReportingComponent,
    WebAppComponent,
)
from .components.base import Finding
from .config import ConfigError, EngagementConfig
from .evidence import EvidenceStore, detectors_available
from .scope import Resolver, ScopeError, ScopeGuard, resolve_host


class Agent:
    def __init__(
        self,
        config: EngagementConfig,
        *,
        auto_approve: bool = False,
        resolver: Resolver = resolve_host,
    ) -> None:
        self.config = config
        self.scope = ScopeGuard(config.scope)
        self._resolver = resolver
        evidence_dir = config.reporting.get("evidence_dir", "evidence")
        self.logger = build_logger(evidence_dir=evidence_dir)
        self.evidence = EvidenceStore(
            evidence_dir=evidence_dir,
            redact_secrets=config.reporting.get("redact_secrets", True),
            logger=self.logger,
        )
        if self.evidence.content_scanning_enabled:
            self.logger.addFilter(RedactingFilter(self.evidence.scan_text))
        self.approval = ApprovalGate(
            config.require_human_approval, auto_yes=auto_approve, logger=self.logger
        )
        deps = (self.scope, self.approval, self.config, self.logger, self.evidence)
        self.reporting = ReportingComponent(*deps)
        self.components = [
            DiscoveryComponent(*deps),
            InfrastructureComponent(*deps),
            WebAppComponent(*deps),
            AutomationComponent(*deps),
            self.reporting,
        ]

    def preflight(self, now: datetime | None = None) -> tuple[list[str], list[str]]:
        """Return ``(blocking problems, warnings)`` before any phase runs."""
        problems = self.config.validate()
        warnings: list[str] = []
        if problems:  # The checks below assume a well-formed scope.
            return problems, warnings

        if not self.scope.in_time_window(now):
            problems.append(
                "Outside every authorized time window: " + ", ".join(self.config.scope.time_windows)
            )

        redact = self.config.reporting.get("redact_secrets", True)
        if redact and not detectors_available():
            message = (
                "Content scanning is unavailable (zero-harm-ai-detectors not importable); "
                "the report would only have key-name masking."
            )
            if self.config.reporting.get("allow_unscanned_report", False):
                warnings.append(message)
            else:
                problems.append(message + " Install it, or set reporting.allow_unscanned_report: true.")

        blocking, dns_warnings = self.scope.resolution_problems(self._resolver)
        problems.extend(blocking)
        warnings.extend(dns_warnings)
        return problems, warnings

    def run(self, now: datetime | None = None) -> list[Finding]:
        targets = self.scope.targets()
        findings: list[Finding] = []
        try:
            # Check every target once, before any phase touches anything.
            for target in targets:
                self.scope.require(target)
            for component in self.components:
                if component is self.reporting:
                    continue
                self.scope.require_time_window(now)
                try:
                    findings.extend(component.run(targets))
                except NotImplementedError:
                    self.logger.info("%s: phase not implemented yet; skipping", component.phase)
        except ScopeError as exc:
            self.logger.error("Aborting run: %s", exc)
            raise
        except Exception:
            self.logger.exception("Aborting run after an unexpected error")
            raise
        finally:
            self.reporting.run(targets)
        return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authorized security testing agent")
    parser.add_argument(
        "--config",
        default="config/engagement.yaml",
        help="Path to the engagement configuration file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config and scope, then exit without running phases.",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Approve actions beyond standing permissions without prompting (use "
             "only for runs you are supervising and have authorized). High-impact "
             "actions still require a human at the terminal.",
    )
    args = parser.parse_args(argv)

    if not Path(args.config).exists():
        print(f"Config not found: {args.config}", file=sys.stderr)
        print("Copy config/engagement.example.yaml and fill it in.", file=sys.stderr)
        return 2

    try:
        config = EngagementConfig.load(args.config)
    except ConfigError as exc:
        print(f"Invalid config: {exc}", file=sys.stderr)
        return 1
    agent = Agent(config, auto_approve=args.auto_approve)

    problems, warnings = agent.preflight()
    for w in warnings:
        print(f"Warning: {w}", file=sys.stderr)
    if problems:
        print("Refusing to run. Fix these first:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"Preflight OK for engagement {config.name!r}.")
        return 0

    try:
        agent.run()
    except ScopeError as exc:
        print(f"Aborting: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
