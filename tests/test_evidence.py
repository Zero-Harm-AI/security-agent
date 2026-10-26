"""Evidence store: key-name masking, content scanning, report serialization."""

import json
import os
import sys

import pytest

from security_agent.components.base import Finding
from security_agent.evidence import EvidenceStore


def test_sensitive_keys_are_masked(tmp_path):
    # Layer 1: value under a sensitive key is masked even with no detectable pattern.
    store = EvidenceStore(str(tmp_path / "ev"), redact_secrets=True)
    store.record(Finding(
        phase="webapp", target="staging.example.com", title="login flow",
        evidence={"password": "hunter2", "note": "visible"},
    ))
    dicts = store.to_dicts()
    assert dicts[0]["evidence"]["password"] == "***REDACTED***"
    assert dicts[0]["evidence"]["note"] == "visible"


@pytest.mark.parametrize("key", [
    "access_token", "client_secret", "X-Api-Key", "Set-Cookie", "Authorization",
    "refresh_token", "db_password", "private_key", "sessionid", "key",
])
def test_sensitive_key_variants_are_masked(tmp_path, key):
    store = EvidenceStore(str(tmp_path / "ev"), redact_secrets=True)
    store.record(Finding("webapp", "t", "x", evidence={"headers": {key: "abc123"}}))
    assert store.to_dicts()[0]["evidence"]["headers"][key] == "***REDACTED***"


def test_non_string_keys_do_not_crash(tmp_path):
    store = EvidenceStore(str(tmp_path / "ev"), redact_secrets=True)
    store.record(Finding("discovery", "t", "x", evidence={22: "ssh", "ports": [80, 443]}))
    assert store.to_dicts()[0]["evidence"][22] == "ssh"


def test_masking_off_when_redaction_disabled(tmp_path):
    store = EvidenceStore(str(tmp_path / "ev"), redact_secrets=False)
    store.record(Finding("webapp", "t", "x", evidence={"password": "hunter2"}))
    assert store.to_dicts()[0]["evidence"]["password"] == "hunter2"


def test_content_scanning_redacts_embedded_pii(tmp_path):
    # Layer 2: zero-harm-ai-detectors scans free text. Skipped if not installed.
    pytest.importorskip("zero_harm_ai_detectors")
    store = EvidenceStore(str(tmp_path / "ev"), redact_secrets=True)
    store.record(Finding(
        phase="discovery", target="t", title="scan",
        evidence={"stdout": "contact found: john@example.com"},
    ))
    scanned = store.to_dicts()[0]["evidence"]["stdout"]
    assert "john@example.com" not in scanned


def test_report_counts_by_confidence(tmp_path):
    store = EvidenceStore(str(tmp_path / "ev"), redact_secrets=True)
    store.record(Finding("discovery", "t", "a", confidence="confirmed"))
    store.record(Finding("discovery", "t", "b", confidence="lead"))
    path = store.write_report()
    report = json.loads(path.read_text())
    assert report["total"] == 2
    assert report["counts"] == {"confirmed": 1, "lead": 1, "inconclusive": 0}
    assert store.counts() == report["counts"]


def test_unknown_confidence_is_rejected():
    with pytest.raises(ValueError):
        Finding("discovery", "t", "x", confidence="confrimed")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_report_is_owner_only(tmp_path):
    store = EvidenceStore(str(tmp_path / "ev"))
    path = store.write_report()
    assert os.stat(path).st_mode & 0o077 == 0


def test_artifact_names_are_sanitized(tmp_path):
    store = EvidenceStore(str(tmp_path / "ev"))
    path = store.save_artifact("../../nmap-10.0.5.0/24.xml", "<x/>")
    assert path.parent == tmp_path / "ev" / "artifacts"
    assert path.read_text() == "<x/>"
