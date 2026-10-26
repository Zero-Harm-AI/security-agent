"""Scope guard fails closed, honors exclusions, time windows, and DNS pinning."""

from datetime import datetime, timezone

import pytest

from security_agent.config import Scope
from security_agent.scope import ScopeError, ScopeGuard
from tests._helpers import fake_resolver


def _guard(**overrides) -> ScopeGuard:
    base = dict(
        domains=["staging.example.com"],
        ip_ranges=["10.0.5.0/24"],
        excluded=["10.0.5.1", "10.0.5.128/25", "old.staging.example.com"],
    )
    base.update(overrides)
    return ScopeGuard(Scope(**base))


def test_authorized_domain_in_scope():
    assert _guard().is_in_scope("staging.example.com")


def test_domain_match_is_case_and_trailing_dot_insensitive():
    assert _guard().is_in_scope("STAGING.Example.com.")


def test_ip_in_authorized_range():
    assert _guard().is_in_scope("10.0.5.42")


def test_unlisted_target_denied():
    assert not _guard().is_in_scope("prod.example.com")


def test_excluded_target_denied_even_if_in_range():
    assert not _guard().is_in_scope("10.0.5.1")


def test_host_inside_excluded_cidr_denied():
    assert not _guard().is_in_scope("10.0.5.200")


def test_cidr_inside_excluded_cidr_denied():
    assert not _guard().is_in_scope("10.0.5.192/26")


def test_excluded_domain_denied():
    g = _guard(domains=["staging.example.com", "old.staging.example.com"])
    assert not g.is_in_scope("old.staging.example.com")


def test_range_containing_exclusions_reports_them():
    # The /24 is authorized, but the caller is told what it must skip.
    assert _guard().require("10.0.5.0/24") == ["10.0.5.1/32", "10.0.5.128/25"]


def test_range_wider_than_authorized_denied():
    assert not _guard().is_in_scope("10.0.0.0/16")


def test_require_raises_for_out_of_scope():
    with pytest.raises(ScopeError):
        _guard().require("8.8.8.8")


def test_no_time_windows_means_unrestricted():
    assert _guard().in_time_window(datetime(2030, 1, 1))


def test_time_window_enforced():
    g = _guard(time_windows=["2026-11-01T00:00Z/2026-11-03T00:00Z"])
    assert g.in_time_window(datetime(2026, 11, 2, tzinfo=timezone.utc))
    assert not g.in_time_window(datetime(2026, 11, 4, tzinfo=timezone.utc))
    with pytest.raises(ScopeError):
        g.require_time_window(datetime(2026, 10, 1, tzinfo=timezone.utc))


def test_domain_resolving_to_excluded_ip_blocks():
    blocking, _ = _guard().resolution_problems(fake_resolver({"staging.example.com": ["10.0.5.1"]}))
    assert blocking


def test_domain_resolving_outside_ranges_warns():
    blocking, warnings = _guard().resolution_problems(
        fake_resolver({"staging.example.com": ["203.0.113.7"]})
    )
    assert not blocking
    assert any("outside the authorized IP ranges" in w for w in warnings)


def test_unresolvable_domain_warns():
    blocking, warnings = _guard().resolution_problems(fake_resolver())
    assert not blocking and warnings
