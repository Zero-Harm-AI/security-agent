"""Agent preflight, wiring, abort handling, audit log, and the CLI."""

import json
from datetime import datetime, timezone

import pytest

from security_agent import agent as agent_mod
from security_agent import evidence as evidence_mod
from security_agent.agent import Agent, main
from security_agent.components.base import Finding
from security_agent.scope import ScopeError
from tests._helpers import fake_resolver, make_config


def _agent(tmp_path, **kw) -> Agent:
    return Agent(make_config(tmp_path, **kw), resolver=fake_resolver())


def test_preflight_passes_for_valid_config(tmp_path):
    problems, _warnings = _agent(tmp_path).preflight()
    assert problems == []


def test_all_phases_are_wired(tmp_path):
    phases = {c.phase for c in _agent(tmp_path).components}
    assert phases == {"discovery", "infrastructure", "webapp", "automation", "reporting"}


def test_run_completes_and_writes_report(tmp_path, monkeypatch):
    # Stubbed phases are skipped; reporting still writes a report.
    monkeypatch.setattr("sys.stdin", None)  # No human: discovery is denied.
    _agent(tmp_path).run()
    report = tmp_path / "evidence" / "report.json"
    assert report.exists()
    assert "findings" in json.loads(report.read_text())


def test_preflight_blocks_outside_time_window(tmp_path):
    a = _agent(tmp_path, time_windows=["2026-11-01T00:00Z/2026-11-03T00:00Z"])
    problems, _ = a.preflight(now=datetime(2026, 12, 1, tzinfo=timezone.utc))
    assert any("time window" in p for p in problems)


def test_run_aborts_outside_time_window_but_writes_report(tmp_path):
    a = _agent(tmp_path, time_windows=["2026-11-01T00:00Z/2026-11-03T00:00Z"])
    with pytest.raises(ScopeError):
        a.run(now=datetime(2026, 12, 1, tzinfo=timezone.utc))
    assert (tmp_path / "evidence" / "report.json").exists()


def test_report_written_when_a_phase_hits_scope_error(tmp_path):
    a = _agent(tmp_path)

    def boom(targets):
        a.evidence.record(Finding("discovery", "10.0.5.9", "found before abort"))
        raise ScopeError("derived target out of scope")

    a.components[0].run = boom
    with pytest.raises(ScopeError):
        a.run()
    report = json.loads((tmp_path / "evidence" / "report.json").read_text())
    assert report["total"] == 1


def test_preflight_blocks_without_content_scanning(tmp_path, monkeypatch):
    monkeypatch.setattr(evidence_mod, "_DETECTORS_AVAILABLE", False)
    monkeypatch.setattr(agent_mod, "detectors_available", lambda: False)
    cfg = make_config(tmp_path)
    cfg.reporting["allow_unscanned_report"] = False
    problems, _ = Agent(cfg, resolver=fake_resolver()).preflight()
    assert any("Content scanning is unavailable" in p for p in problems)

    cfg.reporting["allow_unscanned_report"] = True
    problems, warnings = Agent(cfg, resolver=fake_resolver()).preflight()
    assert problems == [] and any("Content scanning" in w for w in warnings)


def test_preflight_blocks_domain_resolving_to_excluded_ip(tmp_path):
    cfg = make_config(tmp_path, excluded=["10.0.5.1"])
    a = Agent(cfg, resolver=fake_resolver({"staging.example.com": ["10.0.5.1"]}))
    problems, _ = a.preflight()
    assert any("excluded" in p for p in problems)


def test_audit_log_follows_evidence_dir(tmp_path):
    _agent(tmp_path / "one")
    second = _agent(tmp_path / "two")
    second.logger.info("hello from two")
    assert "hello from two" in (tmp_path / "two" / "evidence" / "audit.log").read_text()
    assert "hello from two" not in (tmp_path / "one" / "evidence" / "audit.log").read_text()


def test_audit_log_is_redacted(tmp_path):
    pytest.importorskip("zero_harm_ai_detectors")
    a = _agent(tmp_path)
    a.logger.info("contact %s", "john@example.com")
    assert "john@example.com" not in (tmp_path / "evidence" / "audit.log").read_text()


# --- CLI ---------------------------------------------------------------------

VALID_YAML = """\
engagement: {name: cli, authorized_by: Owner, authorization_ref: T-1}
scope: {domains: [staging.example.com]}
reporting: {evidence_dir: "%s", allow_unscanned_report: true}
"""


def test_cli_missing_config(tmp_path):
    assert main(["--config", str(tmp_path / "nope.yaml")]) == 2


def test_cli_invalid_config(tmp_path, capsys):
    path = tmp_path / "e.yaml"
    path.write_text("scope: {domain: [x]}\n")
    assert main(["--config", str(path)]) == 1
    assert "Invalid config" in capsys.readouterr().err


def test_cli_preflight_failure(tmp_path, capsys):
    path = tmp_path / "e.yaml"
    path.write_text("scope: {domains: [staging.example.com]}\n")
    assert main(["--config", str(path)]) == 1
    assert "Refusing to run" in capsys.readouterr().err


def test_cli_dry_run(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        agent_mod.ScopeGuard, "resolution_problems", lambda self, resolver: ([], [])
    )
    path = tmp_path / "e.yaml"
    path.write_text(VALID_YAML % (tmp_path / "ev"))
    assert main(["--config", str(path), "--dry-run"]) == 0
    assert "Preflight OK" in capsys.readouterr().out
