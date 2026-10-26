"""Discovery phase: command building, scope/approval gating, and nmap handling."""

import subprocess

import pytest

from security_agent.components import discovery
from security_agent.components.discovery import DiscoveryComponent, parse_nmap_xml
from security_agent.scope import ScopeError
from tests._helpers import make_config, make_deps

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.5.10" addrtype="ipv4"/>
    <hostnames><hostname name="web.staging.example.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def fake_nmap(monkeypatch):
    """Pretend nmap is installed and capture the commands it would run."""
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(discovery.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(discovery.subprocess, "run", run)
    return calls


def test_default_command_is_conservative(tmp_path):
    cfg = make_config(tmp_path, active_scanning=False)
    comp = DiscoveryComponent(*make_deps(cfg))
    cmd = comp.build_command("staging.example.com")
    assert cmd[0] == "nmap"
    assert "-Pn" in cmd and "-T2" in cmd
    assert "-sV" not in cmd                       # No version detection by default
    assert "--max-rate" in cmd
    assert cmd[-1] == "staging.example.com"


def test_active_scanning_adds_version_detection(tmp_path):
    cfg = make_config(tmp_path, active_scanning=True)
    comp = DiscoveryComponent(*make_deps(cfg))
    assert "-sV" in comp.build_command("staging.example.com")


def test_option_like_target_is_refused(tmp_path):
    comp = DiscoveryComponent(*make_deps(make_config(tmp_path)))
    with pytest.raises(ValueError):
        comp.build_command("-iL/etc/hosts")


def test_out_of_scope_target_aborts(tmp_path):
    cfg = make_config(tmp_path)
    comp = DiscoveryComponent(*make_deps(cfg))
    with pytest.raises(ScopeError):
        comp.run(["8.8.8.8"])


def test_unapproved_active_scan_is_skipped(tmp_path, fake_nmap):
    # approval required + no human => fail closed => target skipped, nothing recorded
    cfg = make_config(tmp_path, active_scanning=False, require_approval=True)
    deps = make_deps(cfg, auto_yes=False)
    findings = DiscoveryComponent(*deps).run(["staging.example.com"])
    assert findings == []
    assert deps[4].findings == []
    assert fake_nmap == []


def test_scan_needs_approval_without_active_scanning_permission(tmp_path, fake_nmap):
    # Regression: require_human_approval=false must not let an unpermitted scan through.
    cfg = make_config(tmp_path, active_scanning=False, require_approval=False)
    findings = DiscoveryComponent(*make_deps(cfg)).run(["staging.example.com"])
    assert findings == [] and fake_nmap == []


def test_permitted_scan_runs_without_prompt(tmp_path, fake_nmap):
    cfg = make_config(tmp_path, active_scanning=True, require_approval=False)
    findings = DiscoveryComponent(*make_deps(cfg)).run(["staging.example.com"])
    assert len(fake_nmap) == 1
    assert findings[0].title.startswith("Discovery scan completed: 2 open port(s)")


def test_exclusions_are_passed_to_nmap(tmp_path, fake_nmap):
    cfg = make_config(tmp_path, active_scanning=True, require_approval=False,
                      excluded=["10.0.5.1", "10.0.5.128/25"])
    DiscoveryComponent(*make_deps(cfg)).run(["10.0.5.0/24"])
    cmd = fake_nmap[0]
    assert cmd[cmd.index("--exclude") + 1] == "10.0.5.1/32,10.0.5.128/25"
    assert cmd[-1] == "10.0.5.0/24"


def test_open_ports_become_structured_findings(tmp_path, fake_nmap):
    cfg = make_config(tmp_path, active_scanning=True, require_approval=False)
    deps = make_deps(cfg)
    findings = DiscoveryComponent(*deps).run(["10.0.5.0/24"])
    ports = [f for f in findings if f.title.startswith("Open port")]
    assert [p.evidence["port"] for p in ports] == [22, 443]
    assert ports[0].evidence["product"] == "OpenSSH"
    artifact = findings[0].evidence["artifact"]
    assert "nmap-10.0.5.0_24" in artifact
    assert (tmp_path / "evidence" / "artifacts").exists()
    assert len(deps[4].findings) == 3


def test_nmap_missing_records_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda _name: None)
    cfg = make_config(tmp_path, active_scanning=True, require_approval=False)
    findings = DiscoveryComponent(*make_deps(cfg)).run(["staging.example.com"])
    assert findings[0].confidence == "inconclusive"
    assert findings[0].evidence["planned_command"][0] == "nmap"


def test_timeout_records_inconclusive(tmp_path, monkeypatch):
    def run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(discovery.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(discovery.subprocess, "run", run)
    cfg = make_config(tmp_path, active_scanning=True, require_approval=False)
    findings = DiscoveryComponent(*make_deps(cfg)).run(["staging.example.com"])
    assert findings[0].title == "Discovery scan timed out"


def test_os_error_records_inconclusive(tmp_path, monkeypatch):
    def run(cmd, **kwargs):
        raise PermissionError("nmap: permission denied")

    monkeypatch.setattr(discovery.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(discovery.subprocess, "run", run)
    cfg = make_config(tmp_path, active_scanning=True, require_approval=False)
    findings = DiscoveryComponent(*make_deps(cfg)).run(["staging.example.com"])
    assert findings[0].title == "Discovery scan failed to start"


def test_unparseable_output_records_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(
        discovery.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom"),
    )
    cfg = make_config(tmp_path, active_scanning=True, require_approval=False)
    findings = DiscoveryComponent(*make_deps(cfg)).run(["staging.example.com"])
    assert findings[0].confidence == "inconclusive"
    assert "parse_error" in findings[0].evidence


def test_parse_nmap_xml_ignores_closed_ports():
    assert [p["port"] for p in parse_nmap_xml(NMAP_XML)] == [22, 443]
