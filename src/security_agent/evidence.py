"""Evidence store: collect findings and write a redacted report.

Findings are recorded in memory as each phase runs, then serialized by the
reporting phase. Redaction has two layers:

1. Key-name masking: values stored under a key whose name looks sensitive
   (``password``, ``access_token``, ``Set-Cookie``, ``x-api-key``, ...) are
   fully masked, even when their value matches no known pattern.
2. Content scanning: free-text string values are run through the
   ``zero-harm-ai-detectors`` library (heuristic mode), which redacts PII and
   secrets embedded in text such as scan output, URLs, or headers.

If the detector library cannot be imported, layer 2 is unavailable. The agent's
preflight refuses to run in that state unless the engagement sets
``reporting.allow_unscanned_report: true``, and ``report.json`` records
``"content_scanning": false``.

Raw tool output (e.g. nmap XML) is saved next to the report as an artifact. It
is evidence and is kept verbatim; treat the evidence directory as sensitive.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict
from logging import Logger
from pathlib import Path
from typing import Any

# --- Optional content-scanning backend: zero-harm-ai-detectors ---------------
try:
    from zero_harm_ai_detectors import detect as _zhd_detect  # type: ignore
except ImportError:  # library not installed in this environment
    _zhd_detect = None  # type: ignore
    _ZHD_TARGETS: Any = None
else:
    try:
        from zero_harm_ai_detectors import DetectTarget as _DetectTarget  # type: ignore

        _ZHD_TARGETS = _DetectTarget.PII | _DetectTarget.SECRET
    except (ImportError, AttributeError):  # pragma: no cover - attribute shape may vary
        _ZHD_TARGETS = None
_DETECTORS_AVAILABLE = _zhd_detect is not None

# Key names whose values are redacted wholesale when redaction is enabled.
# Matched as a substring of the lowercased key, so "access_token",
# "client_secret", "X-Api-Key" and "Set-Cookie" are all caught.
_SENSITIVE_KEY_RE = re.compile(
    r"passw|passwd|secret|token|api[-_]?key|authoriz|auth[-_]?header|cookie|session"
    r"|credential|private[-_]?key|bearer"
)
_SENSITIVE_EXACT = {"key", "auth", "pwd"}
_REDACTED = "***REDACTED***"
_CONFIDENCE_ORDER = ("confirmed", "lead", "inconclusive")


def is_sensitive_key(key: Any) -> bool:
    name = str(key).lower()
    return name in _SENSITIVE_EXACT or bool(_SENSITIVE_KEY_RE.search(name))


def detectors_available() -> bool:
    return _DETECTORS_AVAILABLE


class EvidenceStore:
    def __init__(
        self,
        evidence_dir: str = "evidence",
        redact_secrets: bool = True,
        logger: Logger | None = None,
    ) -> None:
        self._dir = Path(evidence_dir)
        self._redact = redact_secrets
        self._logger = logger
        self._findings: list[Any] = []

    @property
    def directory(self) -> Path:
        return self._dir

    def record(self, finding: Any) -> None:
        self._findings.append(finding)

    @property
    def findings(self) -> list[Any]:
        return list(self._findings)

    @property
    def content_scanning_enabled(self) -> bool:
        return self._redact and _DETECTORS_AVAILABLE

    def scan_text(self, text: str) -> str:
        """Redact PII/secrets inside a free-text value via zero-harm-ai-detectors."""
        if not self.content_scanning_enabled or _zhd_detect is None:
            return text
        try:
            if _ZHD_TARGETS is not None:
                result = _zhd_detect(text, targets=_ZHD_TARGETS, redaction_strategy="token")
            else:
                result = _zhd_detect(text, redaction_strategy="token")
            return result.redacted_text
        except Exception as exc:  # never let redaction crash reporting
            if self._logger:
                self._logger.warning("evidence: content scan failed (%s); leaving value", exc)
            return text

    def _redact_value(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if self._redact and is_sensitive_key(k):
                    out[k] = _REDACTED
                else:
                    out[k] = self._redact_value(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [self._redact_value(v) for v in obj]
        if isinstance(obj, str):
            return self.scan_text(obj)
        return obj

    def to_dicts(self) -> list[dict[str, Any]]:
        return [self._redact_value(asdict(f)) for f in self._findings]

    def counts(self) -> dict[str, int]:
        counts = dict.fromkeys(_CONFIDENCE_ORDER, 0)
        for f in self._findings:
            confidence = getattr(f, "confidence", "lead")
            counts[confidence] = counts.get(confidence, 0) + 1
        return counts

    def save_artifact(self, name: str, content: str) -> Path:
        """Save raw tool output under <evidence_dir>/artifacts/ and return its path."""
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "artifact"
        directory = self._dir / "artifacts"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / safe
        _write_private(path, content)
        return path

    def write_report(self) -> Path:
        """Write findings to <evidence_dir>/report.json and return its path."""
        self._dir.mkdir(parents=True, exist_ok=True)
        records = self.to_dicts()
        by_confidence: dict[str, list[dict[str, Any]]] = {k: [] for k in _CONFIDENCE_ORDER}
        for r in records:
            by_confidence.setdefault(r.get("confidence", "lead"), []).append(r)
        report = {
            "total": len(records),
            "counts": {k: len(v) for k, v in by_confidence.items()},
            "content_scanning": self.content_scanning_enabled,
            "findings": by_confidence,
        }
        path = self._dir / "report.json"
        _write_private(path, json.dumps(report, indent=2, sort_keys=True, default=str))
        return path


def _write_private(path: Path, content: str) -> None:
    """Write a file readable only by the owner (where the OS supports it)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
