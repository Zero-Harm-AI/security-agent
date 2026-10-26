"""Workflow components, one per phase of the testing workflow.

Each component receives the ScopeGuard, ApprovalGate, config, logger, and
EvidenceStore, and exposes a single ``run`` method that returns a list of
findings. ``discovery`` and ``reporting`` are implemented; ``infrastructure``,
``webapp``, and ``automation`` are still stubs that raise NotImplementedError.
"""

from .automation import AutomationComponent
from .discovery import DiscoveryComponent
from .infrastructure import InfrastructureComponent
from .reporting import ReportingComponent
from .webapp import WebAppComponent

__all__ = [
    "DiscoveryComponent",
    "InfrastructureComponent",
    "WebAppComponent",
    "AutomationComponent",
    "ReportingComponent",
]
