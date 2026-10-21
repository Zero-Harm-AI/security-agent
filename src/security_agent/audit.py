"""Audit logging.

ARCHITECTURE.md requires that every command, request, and output be logged.
This module provides a logger that writes to the console and, when an evidence
directory is configured, to an append-only audit log inside it.
"""

from __future__ import annotations

import logging
from pathlib import Path

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def build_logger(name: str = "security_agent", evidence_dir: str | None = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:  # Already configured; don't double-attach.
        return logger
    logger.setLevel(logging.INFO)

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(_LOG_FORMAT))
    logger.addHandler(console)

    if evidence_dir:
        path = Path(evidence_dir)
        path.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path / "audit.log")
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        logger.addHandler(file_handler)

    return logger
