"""Agent preflight, wiring, and end-to-end pipeline completion."""

import json

from security_agent.agent import Agent
from security_agent.approval import ActionRequest, ApprovalGate
from tests._helpers import make_config


def test_preflight_passes_for_valid_config(tmp_path):
    assert Agent(make_config(tmp_path)).preflight() == []


def test_all_phases_are_wired(tmp_path):
    phases = {c.phase for c in Agent(make_config(tmp_path)).components}
    assert phases == {"discovery", "infrastructure", "webapp", "automation", "reporting"}


def test_run_completes_and_writes_report(tmp_path):
    # Stubbed phases are skipped; reporting still writes a report.
    agent = Agent(make_config(tmp_path))
    agent.run()
    report = tmp_path / "evidence" / "report.json"
    assert report.exists()
    assert "findings" in json.loads(report.read_text())


def test_approval_gate_denies_by_default():
    gate = ApprovalGate(require_human_approval=True)
    assert gate.request(ActionRequest("webapp", "staging.example.com", "scan")) is False
