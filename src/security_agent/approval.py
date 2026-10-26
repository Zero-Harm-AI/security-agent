"""Human-approval gate.

The agent proposes bounded actions; a human confirms anything beyond the
standing permissions before it runs. The rules, in order:

1. ``high_impact`` actions (exploitation, destructive checks, ...) always need
   a human at the terminal. ``--auto-approve`` never covers them.
2. Actions the engagement's permissions do not already allow
   (``permitted=False``) need approval: ``--auto-approve`` or a human.
3. Permitted actions pass, unless ``require_human_approval`` is set, in which
   case they also need approval.

The gate fails closed: if it cannot ask a human (no interactive terminal), it
denies. Every decision is written to the audit log.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from logging import Logger


@dataclass
class ActionRequest:
    phase: str
    target: str
    description: str
    high_impact: bool = False
    # True when the engagement's standing permissions already allow this action.
    permitted: bool = False


def _terminal_prompt(banner: str) -> str | None:
    """Ask on the terminal; None means there is no human to ask."""
    if not sys.stdin or not sys.stdin.isatty():
        return None
    try:
        return input(banner)
    except (EOFError, KeyboardInterrupt):
        return ""


class ApprovalGate:
    def __init__(
        self,
        require_human_approval: bool = True,
        *,
        auto_yes: bool = False,
        logger: Logger | None = None,
        prompt: Callable[[str], str | None] = _terminal_prompt,
    ) -> None:
        self._require = require_human_approval
        self._auto_yes = auto_yes  # For non-interactive runs the operator opted into.
        self._logger = logger
        self._prompt_fn = prompt

    def request(self, action: ActionRequest) -> bool:
        """Return True if the action may proceed."""
        if action.high_impact:
            return self._decide(action, self._prompt(action), "high-impact; human required")
        if action.permitted and not self._require:
            return self._decide(action, True, "within standing permissions")
        if self._auto_yes:
            return self._decide(action, True, "--auto-approve")
        return self._decide(action, self._prompt(action), "human")

    def _decide(self, action: ActionRequest, allowed: bool, reason: str) -> bool:
        if self._logger:
            self._logger.info(
                "approval: %s phase=%s target=%s (%s): %s",
                "APPROVED" if allowed else "DENIED",
                action.phase, action.target, reason, action.description,
            )
        return allowed

    def _prompt(self, action: ActionRequest) -> bool:
        banner = (
            f"\n[APPROVAL] phase={action.phase} target={action.target}\n"
            f"           {action.description}\n"
            f"           high_impact={action.high_impact}\n"
            "Proceed? [y/N] "
        )
        answer = self._prompt_fn(banner)
        if answer is None:  # Fail closed when there is no human to ask.
            return False
        return answer.strip().lower() in {"y", "yes"}
