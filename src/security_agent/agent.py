"""Agent entry point.

Loads an engagement config, enforces scope, and runs the workflow phases in
order. Implemented phases run; phases still stubbed are logged and skipped so
the pipeline completes and the reporting phase can still write a report. The
orchestrator does nothing unattended: anything beyond standing permissions
goes through the human approval gate, and scope violations abort the run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .approval import ApprovalGate
from .audit import build_logger
from .config import EngagementConfig
from .components import (
    AutomationComponent,
    DiscoveryComponent,
    InfrastructureComponent,
    ReportingComponent,
    WebAppComponent,
)
from .components.base import Finding
from .evidence import EvidenceStore
from .scope import ScopeError, ScopeGuard


class Agent:
    def __init__(self, config: EngagementConfig, *, auto_approve: bool = False) -> None:
        self.config = config
        self.scope = ScopeGuard(config.scope)
        self.approval = ApprovalGate(config.require_human_approval, auto_yes=auto_approve)
        evidence_dir = config.reporting.get("evidence_dir", "evidence")
        self.logger = build_logger(evidence_dir=evidence_dir)
        self.evidence = EvidenceStore(
            evidence_dir=evidence_dir,
            redact_secrets=config.reporting.get("redact_secrets", True),
            logger=self.logger,
        )
        deps = (self.scope, self.approval, self.config, self.logger, self.evidence)
        self.components = [
            DiscoveryComponent(*deps),
            InfrastructureComponent(*deps),
            WebAppComponent(*deps),
            AutomationComponent(*deps),
            ReportingComponent(*deps),
        ]

    def preflight(self) -> list[str]:
        """Return blocking problems before any phase runs."""
        return self.config.validate()

    def run(self) -> list[Finding]:
        targets = list(self.config.scope.domains) + list(self.config.scope.ip_ranges)
        findings: list[Finding] = []
        for component in self.components:
            try:
                findings.extend(component.run(targets))
            except NotImplementedError:
                self.logger.info("%s: phase not implemented yet; skipping", component.phase)
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
        help="Approve bounded actions without prompting (use only for runs you "
             "are supervising and have authorized).",
    )
    args = parser.parse_args(argv)

    if not Path(args.config).exists():
        print(f"Config not found: {args.config}", file=sys.stderr)
        print("Copy config/engagement.example.yaml and fill it in.", file=sys.stderr)
        return 2

    config = EngagementConfig.load(args.config)
    agent = Agent(config, auto_approve=args.auto_approve)

    problems = agent.preflight()
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
