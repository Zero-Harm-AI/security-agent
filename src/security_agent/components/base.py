"""Shared base class for workflow components."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from logging import Logger
from typing import Any, Literal, get_args

from ..approval import ApprovalGate
from ..config import EngagementConfig
from ..evidence import EvidenceStore
from ..scope import ScopeGuard

Confidence = Literal["confirmed", "lead", "inconclusive"]


@dataclass
class Finding:
    phase: str
    target: str
    title: str
    confidence: Confidence = "lead"
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.confidence not in get_args(Confidence):
            raise ValueError(
                f"confidence must be one of {get_args(Confidence)}, got {self.confidence!r}"
            )


class Component(ABC):
    #: Human-readable phase name, used in logs and findings.
    phase: str = "base"

    def __init__(
        self,
        scope: ScopeGuard,
        approval: ApprovalGate,
        config: EngagementConfig,
        logger: Logger,
        evidence: EvidenceStore,
    ) -> None:
        self.scope = scope
        self.approval = approval
        self.config = config
        self.logger = logger
        self.evidence = evidence

    @abstractmethod
    def run(self, targets: list[str]) -> list[Finding]:
        """Execute this phase against in-scope targets and return findings."""
        raise NotImplementedError
