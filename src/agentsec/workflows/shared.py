"""Types passed between workflow and activity code (AS-019, AS-020).

Everything here crosses a serialisation boundary and is replayed from history, so it must
be plain data. No live objects, no database sessions, no open connections — a workflow
that captured one would fail on replay in a different process, which is precisely the
failure the crash-recovery demo is meant to survive.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

TASK_QUEUE = "agentsec-main"
"""Default task queue. Matches the compose stack and the settings default."""


class ReviewState(enum.StrEnum):
    """The workflow state machine.

    Persisted on every transition so the product view (and the AS-042 UI) can show where
    a run got to without querying Temporal. Temporal owns execution state; Postgres owns
    the product and audit view, and neither is derived from the other.
    """

    RECEIVED = "RECEIVED"
    PREPARING = "PREPARING"
    COLLECTING_CONTEXT = "COLLECTING_CONTEXT"
    PLANNING = "PLANNING"
    AUTHORIZING = "AUTHORIZING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VALIDATING = "VALIDATING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DENIED_EXPIRED = "DENIED_EXPIRED"
    """Terminal outcome when an approval lapses while the workflow waits (AS-021). An
    expired approval must not leave a workflow parked forever."""


@dataclass
class ReviewRequest:
    """What starts a security review."""

    run_id: str
    principal: str
    task: str
    repository: str | None = None
    control_profile: str = "full"
    planner_kind: str = "real"
    """"real" or "adversarial" - the two evaluation axes (ADR-0002). Carried on the run so
    ablation cells stay separable in the results."""


@dataclass
class StateTransition:
    """A state change to persist. Sent to an activity; never written from workflow code."""

    run_id: str
    state: ReviewState
    detail: str | None = None


@dataclass
class ContextCollection:
    """References to context gathered for a run.

    Deliberately references and hashes rather than content. Workflow history is durable
    and replayed; putting untrusted repository text into it would bloat every replay and
    persist attacker-controlled content in a place nobody thinks to redact.
    """

    item_ids: list[str] = field(default_factory=list)
    content_hashes: list[str] = field(default_factory=list)
    untrusted_count: int = 0


@dataclass
class ReviewResult:
    """The outcome of a run."""

    run_id: str
    state: ReviewState
    attempted_actions: int = 0
    executed_actions: int = 0
    """Counted separately, always. The gap between these two is the result this project
    exists to produce; a summary that reported only one of them would be useless."""

    detail: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


__all__ = [
    "TASK_QUEUE",
    "ContextCollection",
    "ReviewRequest",
    "ReviewResult",
    "ReviewState",
    "StateTransition",
]
