"""Approval gate: permissions, auto-approve limits, fail-closed prompting, logging."""

import logging

from security_agent.approval import ActionRequest, ApprovalGate
from tests._helpers import no_human


def _req(**kw):
    return ActionRequest("discovery", "staging.example.com", "scan", **kw)


def test_denies_by_default_without_a_terminal():
    gate = ApprovalGate(require_human_approval=True, prompt=no_human)
    assert gate.request(_req()) is False


def test_unpermitted_action_needs_approval_even_when_approval_not_required():
    gate = ApprovalGate(require_human_approval=False, prompt=no_human)
    assert gate.request(_req(permitted=False)) is False


def test_permitted_action_passes_when_approval_not_required():
    gate = ApprovalGate(require_human_approval=False, prompt=no_human)
    assert gate.request(_req(permitted=True)) is True


def test_permitted_action_still_prompts_when_approval_required():
    gate = ApprovalGate(require_human_approval=True, prompt=no_human)
    assert gate.request(_req(permitted=True)) is False


def test_auto_approve_covers_normal_actions():
    gate = ApprovalGate(require_human_approval=True, auto_yes=True, prompt=no_human)
    assert gate.request(_req()) is True


def test_auto_approve_never_covers_high_impact():
    gate = ApprovalGate(require_human_approval=False, auto_yes=True, prompt=no_human)
    assert gate.request(_req(high_impact=True, permitted=True)) is False


def test_human_yes_approves_high_impact():
    gate = ApprovalGate(prompt=lambda _b: "y")
    assert gate.request(_req(high_impact=True)) is True


def test_human_anything_but_yes_denies():
    gate = ApprovalGate(prompt=lambda _b: "sure")
    assert gate.request(_req()) is False


def test_decisions_are_logged(caplog):
    logger = logging.getLogger("approval-test")
    gate = ApprovalGate(prompt=no_human, logger=logger)
    with caplog.at_level(logging.INFO, logger="approval-test"):
        gate.request(_req())
    assert "DENIED" in caplog.text and "staging.example.com" in caplog.text
