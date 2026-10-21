"""Config validation blocks empty scope and missing authorization."""

from security_agent.config import EngagementConfig, Permissions, Scope


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


def test_empty_scope_is_blocked():
    problems = _cfg().validate()
    assert any("Scope is empty" in p for p in problems)


def test_missing_authorization_is_blocked():
    problems = _cfg().validate()
    assert any("authorization" in p.lower() for p in problems)


def test_valid_config_has_no_problems():
    cfg = _cfg(
        authorized_by="Owner",
        authorization_ref="TICKET-1",
        scope=Scope(domains=["staging.example.com"]),
    )
    assert cfg.validate() == []
