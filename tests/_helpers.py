"""Shared test helpers."""

from __future__ import annotations

from security_agent.approval import ApprovalGate
from security_agent.audit import build_logger
from security_agent.config import EngagementConfig, Permissions, Scope
from security_agent.evidence import EvidenceStore
from security_agent.scope import ScopeGuard


def no_human(_banner: str) -> None:
    """Approval prompt stand-in for "no terminal": the gate must deny."""
    return None


def fake_resolver(mapping: dict[str, list[str]] | None = None):
    """Resolver that never touches the network."""
    mapping = mapping or {}

    def resolve(name: str) -> list[str]:
        if name not in mapping:
            raise OSError("not in fake DNS")
        return mapping[name]

    return resolve


def make_config(
    tmp_path,
    *,
    active_scanning=False,
    require_approval=True,
    excluded=None,
    time_windows=None,
) -> EngagementConfig:
    return EngagementConfig(
        name="t",
        authorized_by="Owner",
        authorization_ref="TICKET-1",
        scope=Scope(
            domains=["staging.example.com"],
            ip_ranges=["10.0.5.0/24"],
            excluded=list(excluded or []),
            time_windows=list(time_windows or []),
        ),
        permissions=Permissions(active_scanning=active_scanning),
        require_human_approval=require_approval,
        # Tests must pass whether or not zero-harm-ai-detectors is installed.
        reporting={"evidence_dir": str(tmp_path / "evidence"), "allow_unscanned_report": True},
    )


def make_deps(cfg, *, auto_yes=False, prompt=no_human):
    scope = ScopeGuard(cfg.scope)
    logger = build_logger(name="test", evidence_dir=cfg.reporting["evidence_dir"])
    approval = ApprovalGate(cfg.require_human_approval, auto_yes=auto_yes, logger=logger, prompt=prompt)
    evidence = EvidenceStore(cfg.reporting["evidence_dir"], cfg.reporting.get("redact_secrets", True), logger=logger)
    return scope, approval, cfg, logger, evidence
