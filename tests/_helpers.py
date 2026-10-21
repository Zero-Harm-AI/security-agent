"""Shared test helpers."""

from __future__ import annotations

from security_agent.approval import ApprovalGate
from security_agent.audit import build_logger
from security_agent.config import EngagementConfig, Permissions, Scope
from security_agent.evidence import EvidenceStore
from security_agent.scope import ScopeGuard


def make_config(tmp_path, *, active_scanning=False, require_approval=True) -> EngagementConfig:
    return EngagementConfig(
        name="t",
        authorized_by="Owner",
        authorization_ref="TICKET-1",
        scope=Scope(domains=["staging.example.com"], ip_ranges=["10.0.5.0/24"]),
        permissions=Permissions(active_scanning=active_scanning),
        require_human_approval=require_approval,
        reporting={"evidence_dir": str(tmp_path / "evidence")},
    )


def make_deps(cfg, *, auto_yes=False):
    scope = ScopeGuard(cfg.scope)
    approval = ApprovalGate(cfg.require_human_approval, auto_yes=auto_yes)
    logger = build_logger(name="test", evidence_dir=cfg.reporting["evidence_dir"])
    evidence = EvidenceStore(cfg.reporting["evidence_dir"], cfg.reporting.get("redact_secrets", True), logger=logger)
    return scope, approval, cfg, logger, evidence
