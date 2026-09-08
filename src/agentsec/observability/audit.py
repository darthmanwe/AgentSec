"""The audit trail (AS-041).

``audit_events`` has existed since S0 and nothing ever wrote to it. A table nobody writes
is a schema, not an audit trail, and the difference only shows up when someone asks what
actually happened during a run.

The design goal is narrow and worth stating: **the trail must be sufficient to check the
invariant without reading the code that enforced it.** An audit log that merely records
what the enforcement layer believed it did adds ceremony and no assurance — if the
enforcement is wrong, so is the log, in exactly the same direction. So every event records
the *inputs to* a decision alongside its outcome, and :mod:`agentsec.observability.replay`
re-derives the verdict from the trail alone.

What this is not: tamper-evidence. Appending is a service convention, not a database
permission, and an attacker holding database credentials can rewrite history. The threat
model says so plainly. What the trail buys is reconstruction, not proof of integrity.

Everything passes through the AS-003 redactor on the way in. The trail is a place secrets
end up by accident more readily than logs are, because it deliberately records arguments.
"""

from __future__ import annotations

import datetime as dt
import enum
from dataclasses import dataclass, field
from typing import Any, Protocol

from agentsec.log import get_logger
from agentsec.redaction import redact

log = get_logger("agentsec.audit")


class AuditEventType(enum.StrEnum):
    """Every point on the path from proposal to effect.

    Enumerated rather than free-form so replay can assert on the set. A trail whose event
    names are strings invented at each call site cannot be checked for gaps: the absence
    of an event and a typo in its name look identical.
    """

    PLAN_PROPOSED = "plan_proposed"
    """The planner returned actions. Recorded before any of them are authorized."""

    ACTION_COMPILED = "action_compiled"
    """A proposal became a concrete intent with a digest. The digest is the join key for
    everything that follows."""

    ACTION_REFUSED = "action_refused"
    """Refused before reaching policy: unknown tool, malformed, out of scope."""

    POLICY_DECIDED = "policy_decided"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_DECIDED = "approval_decided"
    CAPABILITY_MINTED = "capability_minted"
    CAPABILITY_REDEEMED = "capability_redeemed"
    DISPATCH_DENIED = "dispatch_denied"
    EXECUTED = "executed"
    """An external effect happened. The only event that has to be justified by the ones
    before it."""


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One entry. Immutable, because an audit record that can be edited in flight is a
    note rather than a record."""

    event_type: AuditEventType
    occurred_at: dt.datetime
    run_id: str | None = None
    workflow_id: str | None = None
    action_digest: str | None = None
    principal: str | None = None
    tool: str | None = None
    operation: str | None = None
    outcome: str | None = None
    """The decision, where the event carries one: ALLOW, DENY, REQUIRE_APPROVAL, granted,
    denied, expired. Replay reads this rather than parsing prose."""

    reason: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def as_row(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "occurred_at": self.occurred_at.isoformat(),
            "run_id": self.run_id,
            "workflow_id": self.workflow_id,
            "action_digest": self.action_digest,
            "principal": self.principal,
            "tool": self.tool,
            "operation": self.operation,
            "outcome": self.outcome,
            "reason": self.reason,
            "payload": self.payload,
        }


class AuditSink(Protocol):
    """Where records go.

    A protocol so the evaluation stays database-free. The eval harness runs hundreds of
    control-path traversals with no Postgres anywhere near it, and a trail that required
    one would either force a database into CI or force the eval to skip auditing — and an
    audit path exercised only in production is an audit path that has never been tested.
    """

    def emit(self, record: AuditRecord) -> None: ...


@dataclass
class MemoryAuditSink:
    """Collects records in order. Used by the evaluation and by every test."""

    records: list[AuditRecord] = field(default_factory=list)

    def emit(self, record: AuditRecord) -> None:
        self.records.append(record)

    def for_digest(self, digest: str) -> list[AuditRecord]:
        return [record for record in self.records if record.action_digest == digest]

    def digests(self) -> list[str]:
        seen: list[str] = []
        for record in self.records:
            if record.action_digest and record.action_digest not in seen:
                seen.append(record.action_digest)
        return seen


@dataclass
class NullAuditSink:
    """Discards everything.

    The default, so auditing is opt-in rather than a hidden cost on every code path, and
    so a caller that forgot to pass a sink gets no audit rather than a crash mid-run.
    """

    def emit(self, record: AuditRecord) -> None:
        return None


@dataclass
class LoggingAuditSink:
    """Writes records to the structured log.

    Useful when there is no database and the run still needs to leave a trace on disk —
    which is the demo configuration.
    """

    def emit(self, record: AuditRecord) -> None:
        log.info("audit", **{k: v for k, v in record.as_row().items() if v is not None})


class AuditTrail:
    """Convenience wrapper that stamps time and redacts.

    Every call site would otherwise repeat both, and the one that forgot the redactor
    would be the one recording tool arguments.
    """

    def __init__(self, sink: AuditSink | None = None, *, run_id: str | None = None) -> None:
        self.sink: AuditSink = sink or NullAuditSink()
        self.run_id = run_id

    def emit(
        self,
        event_type: AuditEventType,
        *,
        action_digest: str | None = None,
        workflow_id: str | None = None,
        principal: str | None = None,
        tool: str | None = None,
        operation: str | None = None,
        outcome: str | None = None,
        reason: str | None = None,
        **payload: Any,
    ) -> AuditRecord:
        record = AuditRecord(
            event_type=event_type,
            occurred_at=dt.datetime.now(dt.UTC),
            run_id=self.run_id,
            workflow_id=workflow_id,
            action_digest=action_digest,
            principal=principal,
            tool=tool,
            operation=operation,
            outcome=outcome,
            reason=reason,
            payload=redact(payload),
        )
        self.sink.emit(record)
        return record


__all__ = [
    "AuditEventType",
    "AuditRecord",
    "AuditSink",
    "AuditTrail",
    "LoggingAuditSink",
    "MemoryAuditSink",
    "NullAuditSink",
]
