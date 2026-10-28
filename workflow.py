"""Governed application workflow definitions and transition validation."""
from __future__ import annotations

from dataclasses import dataclass


ACTION_LABELS = {
    "advance": "Advance workflow",
    "request_correction": "Request correction",
    "hold": "Place on hold",
    "resume": "Resume review",
    "resubmit": "Resubmit for review",
    "reject": "Reject application",
}

REASON_REQUIRED_ACTIONS = frozenset(ACTION_LABELS) - {"advance"}


@dataclass(frozen=True)
class Transition:
    action: str
    from_stage: str
    to_stage: str
    status: str


def next_stage(stages: list[str], current_stage: str) -> str:
    """Return the next configured stage, or the current stage at the end."""
    try:
        index = stages.index(current_stage)
    except ValueError as exc:
        raise ValueError(f"Unknown workflow stage: {current_stage}") from exc
    return stages[min(index + 1, len(stages) - 1)]


def resolve_transition(
    stages: list[str],
    current_stage: str,
    current_status: str,
    action: str,
) -> Transition:
    """Validate an action against the current state and return its outcome."""
    if action not in ACTION_LABELS:
        raise ValueError("Unsupported workflow action.")
    if current_stage not in stages:
        raise ValueError("Application has an invalid workflow stage.")
    if current_status in {"Completed", "Rejected"}:
        raise ValueError("Closed applications cannot be changed.")

    if action == "advance":
        target = next_stage(stages, current_stage)
        return Transition(action, current_stage, target, "Completed" if target == stages[-1] else "In Progress")
    if action == "request_correction":
        return Transition(action, current_stage, current_stage, "Returned")
    if action == "hold":
        return Transition(action, current_stage, current_stage, "On Hold")
    if action == "resume":
        if current_status != "On Hold":
            raise ValueError("Only applications on hold can be resumed.")
        return Transition(action, current_stage, current_stage, "In Progress")
    if action == "resubmit":
        if current_status != "Returned":
            raise ValueError("Only returned applications can be resubmitted.")
        return Transition(action, current_stage, current_stage, "In Progress")
    return Transition(action, current_stage, stages[-1], "Rejected")
