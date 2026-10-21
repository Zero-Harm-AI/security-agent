"""Human-approval gate.

The agent proposes bounded actions; a human confirms anything beyond the
standing permissions before it runs. The gate fails closed: if it cannot ask a
human (no interactive terminal), it denies.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass
class ActionRequest:
    phase: str
    target: str
    description: str
    high_impact: bool = False


class ApprovalGate:
    def __init__(self, require_human_approval: bool = True, *, auto_yes: bool = False) -> None:
        self._require = require_human_approval
        self._auto_yes = auto_yes  # For non-interactive runs the operator opted into.

    def request(self, action: ActionRequest) -> bool:
        """Return True if the action may proceed.

        Actions covered by standing permissions (approval not required, not
        high-impact) pass automatically. Everything else needs an explicit yes.
        """
        if not self._require and not action.high_impact:
            return True
        if self._auto_yes:
            return True
        return self._prompt(action)

    def _prompt(self, action: ActionRequest) -> bool:
        # Fail closed when there is no human at the terminal to ask.
        if not sys.stdin or not sys.stdin.isatty():
            return False
        banner = (
            f"\n[APPROVAL] phase={action.phase} target={action.target}\n"
            f"           {action.description}\n"
            f"           high_impact={action.high_impact}\n"
            "Proceed? [y/N] "
        )
        try:
            answer = input(banner).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return answer in {"y", "yes"}
