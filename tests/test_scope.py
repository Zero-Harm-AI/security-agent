"""Scope guard fails closed and honors exclusions."""

from security_agent.config import Scope
from security_agent.scope import ScopeGuard, ScopeError

import pytest


def _guard() -> ScopeGuard:
    return ScopeGuard(
        Scope(
            domains=["staging.example.com"],
            ip_ranges=["10.0.5.0/24"],
            excluded=["10.0.5.1"],
        )
    )


def test_authorized_domain_in_scope():
    assert _guard().is_in_scope("staging.example.com")


def test_ip_in_authorized_range():
    assert _guard().is_in_scope("10.0.5.42")


def test_unlisted_target_denied():
    assert not _guard().is_in_scope("prod.example.com")


def test_excluded_target_denied_even_if_in_range():
    assert not _guard().is_in_scope("10.0.5.1")


def test_require_raises_for_out_of_scope():
    with pytest.raises(ScopeError):
        _guard().require("8.8.8.8")
