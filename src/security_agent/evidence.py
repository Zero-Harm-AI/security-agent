"""Evidence store: collect findings and write a redacted report.

Findings are recorded in memory as each phase runs, then serialized by the
reporting phase. Redaction has two layers:

1. Key-name masking: values stored under an obviously sensitive key
   (``password``, ``token``, ...) are fully masked, even when their value
   matches no known pattern.
2. Content scanning: free-text string values are run through the
   ``zero-harm-ai-detectors`` library (heuristic mode), which redacts PII and
   secrets embedded in text such as scan output, URLs, or headers.

If the detector library is not installed, layer 2 is skipped and only the
key-name masking applies.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from logging import Logger
from pathlib import Path
from typing import Any

# --- Optional content-scanning backend: zero-harm-ai-detectors ---------------
try:
    from zero_harm_ai_detectors import detect as _zhd_detect  # type: ignore

    try:
        from zero_harm_ai_detectors import DetectTarget as _DetectTarget  # type: ignore

        _ZHD_TARGETS: Any = _DetectTarget.PII | _DetectTarget.SECRET
    except Exception:  # pragma: no cover - attribute shape may vary
        _ZHD_TARGETS = None
    _DETECTORS_AVAILABLE = True
except Exception:  # library not installed in this environment
    _zhd_detect = None  # type: ignore
    _ZHD_TARGETS = None
    _DETECTORS_AVAILABLE = False

# Evidence keys whose values are redacted wholesale when redaction is enabled.
_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "authorization",
    "api_key", "apikey", "key", "cookie", "session",
}
_REDACTED = "***REDACTED***"


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

    def record(self, finding: Any) -> None:
        self._findings.append(finding)

    @property
    def findings(self) -> list[Any]:
        return list(self._findings)

    @property
    def content_scanning_enabled(self) -> bool:
        return self._redact and _DETECTORS_AVAILABLE

    def _scan_text(self, text: str) -> str:
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
                if self._redact and k.lower() in _SENSITIVE_KEYS:
                    out[k] = _REDACTED
                else:
                    out[k] = self._redact_value(v)
            return out
        if isinstance(obj, list):
            return [self._redact_value(v) for v in obj]
        if isinstance(obj, str):
            return self._scan_text(obj)
        return obj

    def to_dicts(self) -> list[dict[str, Any]]:
        return [self._redact_value(asdict(f)) for f in self._findings]

    def write_report(self) -> Path:
        """Write findings to <evidence_dir>/report.json and return its path."""
        self._dir.mkdir(parents=True, exist_ok=True)
        records = self.to_dicts()
        by_confidence: dict[str, list[dict[str, Any]]] = {
            "confirmed": [], "lead": [], "inconclusive": [],
        }
        for r in records:
            by_confidence.setdefault(r.get("confidence", "lead"), []).append(r)
        report = {
            "total": len(records),
            "counts": {k: len(v) for k, v in by_confidence.items()},
            "content_scanning": self.content_scanning_enabled,
            "findings": by_confidence,
        }
        path = self._dir / "report.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True))
        return path
