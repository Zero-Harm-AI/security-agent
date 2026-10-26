"""Config loading is strict; validation blocks unsafe or malformed engagements."""

import textwrap

import pytest

from security_agent.config import ConfigError, EngagementConfig, Permissions, Scope


def _cfg(**overrides):
    base = dict(
        name="t",
        authorized_by="",
        authorization_ref="",
        scope=Scope(),
        permissions=Permissions(),
    )
    base.update(overrides)
    return EngagementConfig(**base)


def _valid(**scope):
    return _cfg(
        authorized_by="Owner",
        authorization_ref="TICKET-1",
        scope=Scope(**{"domains": ["staging.example.com"], **scope}),
    )


def _load(tmp_path, body: str) -> EngagementConfig:
    path = tmp_path / "engagement.yaml"
    path.write_text(textwrap.dedent(body))
    return EngagementConfig.load(path)


def test_empty_scope_is_blocked():
    problems = _cfg().validate()
    assert any("Scope is empty" in p for p in problems)


def test_missing_authorization_is_blocked():
    problems = _cfg().validate()
    assert any("authorization" in p.lower() for p in problems)


def test_valid_config_has_no_problems():
    assert _valid().validate() == []


@pytest.mark.parametrize("field,value", [
    ("domains", ["-iL/etc/hosts"]),
    ("domains", ["bad host.example.com"]),
    ("ip_ranges", ["10.0.5.0/33"]),
    ("excluded", ["not a target!"]),
    ("time_windows", ["2026-11-03T00:00/2026-11-01T00:00"]),
    ("time_windows", ["tomorrow"]),
    ("rate_limit_rps", 0),
])
def test_malformed_scope_entries_are_blocked(field, value):
    assert _valid(**{field: value}).validate()


def test_example_config_loads(tmp_path):
    from pathlib import Path
    example = Path(__file__).resolve().parents[1] / "config" / "engagement.example.yaml"
    cfg = EngagementConfig.load(example)
    assert cfg.permissions.active_scanning is False


def test_load_valid_yaml(tmp_path):
    cfg = _load(tmp_path, """
        engagement: {name: x, authorized_by: Owner, authorization_ref: T-1}
        scope: {domains: [staging.example.com], ip_ranges: [10.0.5.0/24]}
        permissions: {active_scanning: true}
        reporting: {evidence_dir: ev}
        require_human_approval: false
    """)
    assert cfg.permissions.active_scanning is True
    assert cfg.require_human_approval is False
    assert cfg.validate() == []


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="domain"):
        _load(tmp_path, "scope: {domain: [staging.example.com]}\n")


def test_unknown_top_level_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        _load(tmp_path, "permisions: {active_scanning: false}\n")


@pytest.mark.parametrize("value", ['"no"', '"false"', "1", "yes please"])
def test_permission_must_be_a_real_bool(tmp_path, value):
    with pytest.raises(ConfigError, match="active_scanning"):
        _load(tmp_path, f"permissions: {{active_scanning: {value}}}\n")


def test_require_human_approval_must_be_a_bool(tmp_path):
    with pytest.raises(ConfigError):
        _load(tmp_path, 'require_human_approval: "false"\n')


def test_scope_lists_must_be_lists_of_strings(tmp_path):
    with pytest.raises(ConfigError):
        _load(tmp_path, "scope: {domains: staging.example.com}\n")


def test_invalid_yaml_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError):
        _load(tmp_path, "scope: [unclosed\n")
