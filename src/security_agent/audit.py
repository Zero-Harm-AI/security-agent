"""Audit logging.

docs/SECURITY-TESTING-ARCHITECTURE.md requires that every command, request,
and output be logged. This module provides a logger that writes to the console
and, when an evidence directory is configured, appends to ``audit.log`` inside
it. A redaction filter can be attached so the log is scrubbed the same way as
the report.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class RedactingFilter(logging.Filter):
    """Pass every formatted log message through a redaction function."""

    def __init__(self, redact: Callable[[str], str]) -> None:
        super().__init__()
        self._redact = redact

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redact(record.getMessage())
        record.args = None
        return True


def build_logger(name: str = "security_agent", evidence_dir: str | None = None) -> logging.Logger:
    """Return the named logger, (re)pointed at ``evidence_dir``.

    Loggers are process-wide singletons, so any handlers from an earlier call
    are closed and replaced; otherwise a second engagement in the same process
    would keep writing to the first one's audit.log.
    """
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    for f in list(logger.filters):
        logger.removeFilter(f)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(_LOG_FORMAT))
    logger.addHandler(console)

    if evidence_dir:
        path = Path(evidence_dir)
        path.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path / "audit.log", mode="a", encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        logger.addHandler(file_handler)

    return logger
