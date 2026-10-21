"""Workflow components, one per phase of the testing workflow.

Each component receives the ScopeGuard and ApprovalGate and exposes a single
``run`` method that returns a list of findings/leads. All are stubs.
"""

from .discovery import DiscoveryComponent
from .infrastructure import InfrastructureComponent
from .webapp import WebAppComponent
from .automation import AutomationComponent
from .reporting import ReportingComponent

__all__ = [
    "DiscoveryComponent",
    "InfrastructureComponent",
    "WebAppComponent",
    "AutomationComponent",
    "ReportingComponent",
]
