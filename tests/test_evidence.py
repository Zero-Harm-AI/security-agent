"""Evidence store: key-name masking, content scanning, report serialization."""

import json

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
    assert report["counts"]["confirmed"] == 1
    assert report["counts"]["lead"] == 1
