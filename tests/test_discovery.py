"""Discovery phase: command building and scope/approval gating."""

from security_agent.components.discovery import DiscoveryComponent
from security_agent.scope import ScopeError
from tests._helpers import make_config, make_deps

import pytest


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


def test_out_of_scope_target_aborts(tmp_path):
    cfg = make_config(tmp_path)
    comp = DiscoveryComponent(*make_deps(cfg))
    with pytest.raises(ScopeError):
        comp.run(["8.8.8.8"])


def test_unapproved_active_scan_is_skipped(tmp_path):
    # approval required + non-tty => fail closed => target skipped, nothing recorded
    cfg = make_config(tmp_path, active_scanning=False, require_approval=True)
    deps = make_deps(cfg, auto_yes=False)
    comp = DiscoveryComponent(*deps)
    findings = comp.run(["staging.example.com"])
    assert findings == []
    assert deps[4].findings == []
