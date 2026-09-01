"""Persistence model for the control plane (AS-005).

Scope is deliberately limited to what S0 and S1 consume. ``tool_executions``,
``model_calls``, ``findings`` and ``artifacts`` are created by the issues that first use
them — writing their migrations now would guarantee rewriting them once M6 defines what
they actually hold.

The schema encodes the distinction the whole project rests on:

* ``action_attempts`` records what was *proposed*, always, including everything denied.
* ``execution_ledger`` records what actually *executed*, at most once per logical
  operation.

Counting rows in the first and rows in the second is what produces the headline result.
A design where denied proposals are simply not written would make the security claim
unmeasurable.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentsec.db.base import Base, DigestColumn, JSONColumn, TimestampColumn


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    """Store enums as VARCHAR + CHECK rather than a native database enum.

    Native PostgreSQL enums require an ALTER TYPE to add a value, which Alembic cannot
    run inside a transaction on older servers and which makes downgrades awkward. A
    checked string is portable and migrates without ceremony.
    """
    return Enum(enum_cls, name=name, native_enum=False, validate_strings=True, length=32)


# --------------------------------------------------------------------------- enums


class RunStatus(enum.StrEnum):
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


class PolicyOutcome(enum.StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class AttemptOutcome(enum.StrEnum):
    """What became of a proposed action.

    ``DENIED_*`` values are the interesting ones: they are the evidence that an attempt
    was made and stopped. They are never deleted or collapsed into a single failure state,
    because the reason for a denial is the measurement.
    """

    EXECUTED = "EXECUTED"
    DENIED_POLICY = "DENIED_POLICY"
    DENIED_NO_CAPABILITY = "DENIED_NO_CAPABILITY"
    DENIED_CAPABILITY_EXPIRED = "DENIED_CAPABILITY_EXPIRED"
    DENIED_CAPABILITY_REPLAYED = "DENIED_CAPABILITY_REPLAYED"
    DENIED_DIGEST_MISMATCH = "DENIED_DIGEST_MISMATCH"
    DENIED_APPROVAL_MISSING = "DENIED_APPROVAL_MISSING"
    DENIED_APPROVAL_EXPIRED = "DENIED_APPROVAL_EXPIRED"
    DENIED_UNKNOWN_TOOL = "DENIED_UNKNOWN_TOOL"
    DENIED_INVALID_ARGUMENTS = "DENIED_INVALID_ARGUMENTS"
    DENIED_PRECONDITION_CHANGED = "DENIED_PRECONDITION_CHANGED"
    FAILED_BACKEND = "FAILED_BACKEND"


class ApprovalState(enum.StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class ExecutionState(enum.StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class TrustLabel(enum.StrEnum):
    """Provenance of a piece of context. Nothing acquires authority by saying so."""

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    MODEL_GENERATED = "MODEL_GENERATED"


# --------------------------------------------------------------------------- mixins


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False, index=True
    )
    """Database time, not application time. An audit trail whose ordering depends on
    client clock skew is not an audit trail."""


# --------------------------------------------------------------------------- tables


class Run(TimestampMixin, Base):
    """One security review, from task to report."""

    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    status: Mapped[RunStatus] = mapped_column(
        _enum(RunStatus, "run_status"), nullable=False, default=RunStatus.RECEIVED
    )
    principal: Mapped[str] = mapped_column(String(255), nullable=False)
    task: Mapped[str] = mapped_column(Text, nullable=False)
    repository: Mapped[str | None] = mapped_column(String(512))

    #: Which control stack this run executed under, so ablation cells stay separable.
    control_profile: Mapped[str | None] = mapped_column(String(64), index=True)
    #: "real" or "adversarial" - the two evaluation axes (ADR-0002).
    planner_kind: Mapped[str | None] = mapped_column(String(32), index=True)

    #: Hashes of the trusted inputs in force, so a run can be reconstructed exactly.
    policy_bundle_hash: Mapped[str | None] = mapped_column(DigestColumn)
    tool_registry_hash: Mapped[str | None] = mapped_column(DigestColumn)
    prompt_registry_hash: Mapped[str | None] = mapped_column(DigestColumn)

    finished_at: Mapped[dt.datetime | None] = mapped_column(TimestampColumn)
    config_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONColumn)

    action_plans: Mapped[list[ActionPlan]] = relationship(back_populates="run")
    attempts: Mapped[list[ActionAttempt]] = relationship(back_populates="run")


class ActionPlan(TimestampMixin, Base):
    """A typed plan emitted by a planner. Never a licence to execute."""

    __tablename__ = "action_plans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(nullable=False)
    """Replan ordinal. A denial may produce a revised plan; both are retained."""

    steps: Mapped[dict[str, Any]] = mapped_column(JSONColumn, nullable=False)
    planner_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    prompt_version: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(128))
    """The model id actually returned by the provider, not the one requested."""

    run: Mapped[Run] = relationship(back_populates="action_plans")

    __table_args__ = (UniqueConstraint("run_id", "sequence"),)


class ActionAttempt(TimestampMixin, Base):
    """Every action a planner proposed, including - especially - the denied ones.

    This table is the denominator of the headline metric. An implementation that only
    recorded successful actions would make the security claim unmeasurable.
    """

    __tablename__ = "action_attempts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_digest: Mapped[str] = mapped_column(DigestColumn, nullable=False, index=True)
    plan_step_occurrence: Mapped[int] = mapped_column(nullable=False, default=0)
    """Distinguishes two intentionally identical actions in one run, so they do not
    collide in the execution ledger."""

    tool: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    operation: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(512), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONColumn, nullable=False)
    preconditions: Mapped[dict[str, Any] | None] = mapped_column(JSONColumn)
    """Immutable world state the approval was bound to: commit SHA, PR head, ETag."""

    outcome: Mapped[AttemptOutcome] = mapped_column(
        _enum(AttemptOutcome, "attempt_outcome"), nullable=False, index=True
    )
    denial_reason: Mapped[str | None] = mapped_column(String(255))
    was_executed: Mapped[bool] = mapped_column(nullable=False, default=False, index=True)
    """Denormalised from ``outcome`` on purpose: the attempt-versus-execution query is
    the single most important one in the project and must not depend on remembering
    which of a dozen outcome values count as execution."""

    run: Mapped[Run] = relationship(back_populates="attempts")

    __table_args__ = (
        Index("ix_action_attempts_run_digest", "run_id", "action_digest"),
        CheckConstraint(
            # `NOT was_executed` rather than `was_executed = 0`: PostgreSQL has no
            # boolean-to-integer comparison, and this form is valid on both backends.
            "NOT was_executed OR outcome = 'EXECUTED'",
            name="executed_flag_matches_outcome",
        ),
    )


class PolicyDecision(TimestampMixin, Base):
    """An OPA decision. Retained whether it allowed, denied, or required approval."""

    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_digest: Mapped[str] = mapped_column(DigestColumn, nullable=False, index=True)
    outcome: Mapped[PolicyOutcome] = mapped_column(
        _enum(PolicyOutcome, "policy_outcome"), nullable=False, index=True
    )
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    obligations: Mapped[dict[str, Any] | None] = mapped_column(JSONColumn)
    policy_bundle_hash: Mapped[str | None] = mapped_column(DigestColumn)
    engine_latency_ms: Mapped[float | None] = mapped_column()

    fail_closed: Mapped[bool] = mapped_column(nullable=False, default=False)
    """True when this DENY came from the engine being unreachable or malformed rather
    than from a rule. Distinguishing the two matters: a spike in fail-closed denials is
    an outage, not an attack."""


class Approval(TimestampMixin, Base):
    """Human authorisation bound to one exact action."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_digest: Mapped[str] = mapped_column(DigestColumn, nullable=False, index=True)
    approval_context_digest: Mapped[str] = mapped_column(DigestColumn, nullable=False)
    """Covers the evidence snapshot actually shown to the operator, so what a human saw
    when approving is provable rather than assumed."""

    state: Mapped[ApprovalState] = mapped_column(
        _enum(ApprovalState, "approval_state"), nullable=False, default=ApprovalState.PENDING
    )
    approver_principal: Mapped[str | None] = mapped_column(String(255))
    evidence_refs: Mapped[dict[str, Any] | None] = mapped_column(JSONColumn)

    expires_at: Mapped[dt.datetime] = mapped_column(TimestampColumn, nullable=False, index=True)
    decided_at: Mapped[dt.datetime | None] = mapped_column(TimestampColumn)
    decision_note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(
            "(state = 'PENDING') OR (approver_principal IS NOT NULL) OR (state = 'EXPIRED')",
            name="decided_approval_has_an_approver",
        ),
    )


class CapabilityGrant(TimestampMixin, Base):
    """A short-lived, narrowly scoped authority token.

    Every binding claim is stored, not merely the signature, so a rejected grant can be
    explained precisely rather than as a generic verification failure.
    """

    __tablename__ = "capability_grants"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approval_id: Mapped[str | None] = mapped_column(ForeignKey("approvals.id"))

    action_digest: Mapped[str] = mapped_column(DigestColumn, nullable=False, index=True)
    request_hash: Mapped[str] = mapped_column(DigestColumn, nullable=False)
    """Binds the grant to one request body, so a jti cannot be moved to a different call."""

    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    audience: Mapped[str] = mapped_column(String(255), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(512), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONColumn, nullable=False)

    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    registry_hash: Mapped[str | None] = mapped_column(DigestColumn)
    policy_bundle_hash: Mapped[str | None] = mapped_column(DigestColumn)

    issued_at: Mapped[dt.datetime] = mapped_column(TimestampColumn, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(TimestampColumn, nullable=False, index=True)


class CapabilityJtiUse(Base):
    """Single-use redemption record.

    The primary key *is* the enforcement: a second redemption of the same ``jti`` violates
    the constraint and the database rejects it, rather than relying on a read-then-write
    that two concurrent gateway calls could both pass.

    Retries do not fail against this, because the execution ledger is consulted first and
    a completed operation returns its cached result without reaching redemption.
    """

    __tablename__ = "capability_jti_uses"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    redeemed_at: Mapped[dt.datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False
    )
    operation_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    request_hash: Mapped[str] = mapped_column(DigestColumn, nullable=False)


class ExecutionLedger(TimestampMixin, Base):
    """At-most-once record of a logical side effect.

    Keyed on ``operation_id`` = workflow id + action digest + plan step occurrence. The
    occurrence ordinal matters: two intentionally identical actions in one workflow are
    different operations and must not collide.

    Consulted **before** capability redemption. This ordering is what lets single-use
    grants coexist with Temporal retries - a retry whose operation already completed
    returns the cached result and never reaches the jti check.
    """

    __tablename__ = "execution_ledger"

    operation_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workflow_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action_digest: Mapped[str] = mapped_column(DigestColumn, nullable=False, index=True)
    plan_step_occurrence: Mapped[int] = mapped_column(nullable=False, default=0)

    state: Mapped[ExecutionState] = mapped_column(
        _enum(ExecutionState, "execution_state"), nullable=False, default=ExecutionState.PENDING
    )
    attempt_count: Mapped[int] = mapped_column(nullable=False, default=1)
    """Retries increment this while the logical effect stays at one. The gap between this
    and the row count is the idempotency evidence."""

    request_hash: Mapped[str] = mapped_column(DigestColumn, nullable=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONColumn)
    external_ref: Mapped[str | None] = mapped_column(String(512))
    """Identifier returned by the backend - Jira key, comment id - used to reconcile a
    lost acknowledgement without writing twice."""

    completed_at: Mapped[dt.datetime | None] = mapped_column(TimestampColumn)
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_execution_ledger_workflow_digest", "workflow_id", "action_digest"),)


class AuditEvent(Base):
    """Append-only audit trail.

    Append-only by service convention rather than by database permission, which the threat
    model states plainly: an attacker with database credentials can rewrite history. What
    this buys is a reconstructable run for AS-041 replay, not tamper-evidence.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    occurred_at: Mapped[dt.datetime] = mapped_column(
        TimestampColumn, server_default=func.now(), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    run_id: Mapped[str | None] = mapped_column(String(64), index=True)
    workflow_id: Mapped[str | None] = mapped_column(String(255), index=True)
    action_digest: Mapped[str | None] = mapped_column(DigestColumn, index=True)
    principal: Mapped[str | None] = mapped_column(String(255))
    tool: Mapped[str | None] = mapped_column(String(128))

    trust_label: Mapped[TrustLabel | None] = mapped_column(_enum(TrustLabel, "trust_label"))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONColumn, nullable=False)
    """Passed through the AS-003 redactor before it is written. Secrets must not reach
    this table any more than they reach a log."""


__all__ = [
    "ActionAttempt",
    "ActionPlan",
    "Approval",
    "ApprovalState",
    "AttemptOutcome",
    "AuditEvent",
    "CapabilityGrant",
    "CapabilityJtiUse",
    "ExecutionLedger",
    "ExecutionState",
    "PolicyDecision",
    "PolicyOutcome",
    "Run",
    "RunStatus",
    "TrustLabel",
]
