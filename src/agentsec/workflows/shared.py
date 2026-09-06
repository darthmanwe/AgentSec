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

    approval_ttl_seconds: int = 900
    """How long an operator has to decide before the run gives up.

    Per-run rather than global because the right answer depends on the action: a bounded
    wait is the requirement, and fifteen minutes is a default, not a law."""

    approval_poll_seconds: float = 30.0
    """How often a workflow waiting on approval re-reads the database.

    A safety net, not the primary path: the update handler wakes the workflow immediately.
    This bounds how long a *lost* notification can stall a run, so a dropped signal costs
    latency rather than correctness. Carried on the request rather than read from settings
    because workflow code may not read configuration - that is I/O, and it would change
    between replays."""


@dataclass
class StateTransition:
    """A state change to persist. Sent to an activity; never written from workflow code."""

    run_id: str
    state: ReviewState
    detail: str | None = None


@dataclass
class PlannedAction:
    """One action a planner proposes. A proposal, never a licence to act.

    Carries its own canonical digest (AS-007) because the digest is what an approval and
    a capability bind to. Computing it in the activity that produces the plan means the
    workflow never has to canonicalise anything, which keeps that logic on the I/O side
    of the determinism boundary where it belongs.
    """

    action_id: str
    action_digest: str
    tool: str
    resource: str
    summary: str
    requires_approval: bool = False


@dataclass
class ApprovalRequest:
    """Ask a human to authorise one exact action."""

    run_id: str
    action_digest: str
    summary: str
    ttl_seconds: int = 900


@dataclass
class ApprovalHandle:
    """The approval record the workflow is waiting on.

    ``expires_at`` is the value the database actually stored, not a TTL the workflow
    re-derives. Two clocks computing "now + 900s" independently disagree by however far
    apart they are, and the disagreement decides whether a decision made near the boundary
    counts. One authoritative instant, read back, removes the question.
    """

    approval_id: str
    action_digest: str
    expires_at: str


@dataclass
class ApprovalNudge:
    """Payload of the update/signal that wakes a waiting workflow.

    **It carries no authority.** The workflow re-reads the decision from the database on
    every wake, because that is where operator authentication and decision terminality are
    enforced (AS-010). Anyone able to reach the Temporal namespace can send this; nobody
    can approve anything with it. The fields exist so the update validator can reject a
    nudge aimed at a different action without that rejection reaching workflow history.
    """

    approval_id: str
    action_digest: str


@dataclass
class ApprovalOutcome:
    """The authoritative answer, read from the database."""

    approval_id: str
    decided: bool
    permitted: bool
    reason: str
    approver_principal: str | None = None
    expired: bool = False


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
    "ApprovalHandle",
    "ApprovalNudge",
    "ApprovalOutcome",
    "ApprovalRequest",
    "ContextCollection",
    "PlannedAction",
    "ReviewRequest",
    "ReviewResult",
    "ReviewState",
    "StateTransition",
]
