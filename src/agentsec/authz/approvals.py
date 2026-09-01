"""Exact-action approval (AS-010).

An approval authorises **one action**, identified by its canonical digest (AS-007). It is
not a role, not a session, and not a general permission to act on a resource.

Design points that carry real weight:

**Resolution returns a reason, never a bare boolean.** ``permitted`` is one field of a
result that also says *why*. A call site that only checks a boolean cannot tell "no
approval exists" from "the approval expired", and those need different handling and
produce different metrics.

**A decided approval cannot be re-decided.** Without that, an attacker who reached the
approval API could flip a DENIED record to APPROVED and reuse the original operator's
identity. Decisions are terminal.

**The evidence the operator saw is hashed separately.** ``approval_context_digest`` covers
the evidence snapshot rendered to the human. The action digest proves *what* was approved;
the context digest proves *what the approver was looking at when they approved it*. Those
are different claims and both matter in an audit.

Operator authentication here is a shared token compared in constant time. It is
demo-grade and documented as such in the threat model — the point of this project is
authorization, not building an identity provider.
"""

from __future__ import annotations

import datetime as dt
import enum
import hashlib
import hmac
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentsec.authz.digest import digests_match
from agentsec.authz.models import ContextItem, Principal, PrincipalKind
from agentsec.db.models import Approval, ApprovalState
from agentsec.log import get_logger

log = get_logger("agentsec.authz.approvals")

CONTEXT_DIGEST_DOMAIN: Final = "agentsec.approval.context.v1"

Clock = Callable[[], dt.datetime]


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def as_aware(value: dt.datetime) -> dt.datetime:
    """Attach UTC to a naive datetime read back from storage.

    PostgreSQL returns ``timestamptz`` values already aware; SQLite has no timezone type
    and returns them naive. Comparing a naive value against an aware one raises, so an
    expiry check that worked in production would crash in the test suite — or, with a
    different comparison order, silently compare wall-clock readings from two zones.

    Values are only ever *written* as UTC, so attaching UTC here restores the original
    meaning rather than guessing at one.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)


class ApprovalReason(enum.StrEnum):
    """Why an approval resolution came out the way it did.

    Values are stable identifiers because they are aggregated in reports. The denial
    reasons are deliberately granular: "no approval" and "expired approval" look identical
    to a caller checking a boolean, but one is a missing step and the other is an operator
    who took too long.
    """

    APPROVED = "approval_granted"
    NOT_FOUND = "approval_not_found"
    PENDING = "approval_pending"
    DENIED = "approval_denied_by_operator"
    EXPIRED = "approval_expired"
    DIGEST_MISMATCH = "approval_digest_mismatch"
    WORKFLOW_MISMATCH = "approval_workflow_mismatch"


@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    """The answer to "may this exact action proceed?"."""

    permitted: bool
    reason: ApprovalReason
    approval_id: str | None = None
    approver_principal: str | None = None
    state: ApprovalState | None = None

    def __post_init__(self) -> None:
        if self.permitted and self.reason is not ApprovalReason.APPROVED:
            raise ValueError("a permitted resolution must carry the APPROVED reason")


class ApprovalError(Exception):
    """Raised for misuse of the approval API, never for a negative decision.

    A denial is a value; an error means the caller did something structurally wrong, such
    as trying to re-decide a terminal approval.
    """


def compute_context_digest(items: Sequence[ContextItem]) -> str:
    """Hash the evidence snapshot shown to the operator.

    Covers each item's identity, source, trust label and content hash — not the raw text,
    which may be large and may be attacker-controlled. Sorted by item id so the digest does
    not depend on the order the UI happened to render.
    """
    parts = sorted(
        f"{item.id}\x1f{item.source}\x1f{item.trust.value}\x1f{item.content_hash}" for item in items
    )
    material = CONTEXT_DIGEST_DOMAIN + "\n" + "\x1e".join(parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def authenticate_operator(
    presented_token: str | None,
    expected_token: str | None,
    *,
    operator_id: str = "operator",
) -> Principal | None:
    """Authenticate the approving operator against a shared token.

    Demo-grade by design, and stated as such in the threat model. Two properties still
    matter and are implemented: the comparison is constant-time, and an unconfigured
    expected token authenticates nobody rather than everybody — the failure mode of a
    missing secret must be "no access", not "open access".
    """
    if not expected_token or not presented_token:
        return None
    if not hmac.compare_digest(presented_token, expected_token):
        return None
    return Principal(id=operator_id, kind=PrincipalKind.OPERATOR)


class ApprovalService:
    """Creates approvals and resolves whether an exact action may proceed."""

    def __init__(self, session: AsyncSession, *, clock: Clock = _utc_now) -> None:
        self._session = session
        self._clock = clock

    async def create(
        self,
        *,
        run_id: str,
        action_digest: str,
        context_items: Sequence[ContextItem] = (),
        ttl_seconds: int = 900,
        evidence_refs: dict[str, Any] | None = None,
    ) -> Approval:
        """Open a pending approval for one exact action."""
        now = self._clock()
        approval = Approval(
            id=f"ap-{uuid.uuid4().hex[:16]}",
            run_id=run_id,
            action_digest=action_digest,
            approval_context_digest=compute_context_digest(context_items),
            state=ApprovalState.PENDING,
            expires_at=now + dt.timedelta(seconds=ttl_seconds),
            evidence_refs=evidence_refs,
        )
        self._session.add(approval)
        await self._session.flush()
        log.info(
            "approval requested",
            approval_id=approval.id,
            run_id=run_id,
            action_digest=action_digest,
            expires_at=approval.expires_at.isoformat(),
        )
        return approval

    async def decide(
        self,
        approval_id: str,
        *,
        approver: Principal,
        approved: bool,
        note: str | None = None,
    ) -> Approval:
        """Record an operator's decision. Terminal: a decided approval cannot be re-decided."""
        if not approver.may_approve:
            # The core invariant, enforced here as well as in the type. An agent principal
            # reaching this method is either a bug or an escalation attempt.
            raise ApprovalError(
                f"principal {approver.id!r} of kind {approver.kind.value!r} cannot approve; "
                "only an operator may"
            )

        approval = await self._session.get(Approval, approval_id)
        if approval is None:
            raise ApprovalError(f"approval {approval_id!r} does not exist")

        if approval.state is not ApprovalState.PENDING:
            # Without this, an attacker reaching the approval API could flip a DENIED
            # record to APPROVED and inherit the original operator's identity.
            raise ApprovalError(
                f"approval {approval_id!r} is already {approval.state.value}; "
                "decisions are terminal"
            )

        now = self._clock()
        if now >= as_aware(approval.expires_at):
            approval.state = ApprovalState.EXPIRED
            await self._session.flush()
            raise ApprovalError(f"approval {approval_id!r} expired at {approval.expires_at}")

        approval.state = ApprovalState.APPROVED if approved else ApprovalState.DENIED
        approval.approver_principal = approver.id
        approval.decided_at = now
        approval.decision_note = note
        await self._session.flush()

        log.info(
            "approval decided",
            approval_id=approval.id,
            state=approval.state.value,
            approver=approver.id,
            action_digest=approval.action_digest,
        )
        return approval

    async def resolve(
        self,
        *,
        action_digest: str,
        run_id: str | None = None,
    ) -> ApprovalResolution:
        """Decide whether this exact action has a usable approval.

        Looks up **by digest**, so an approval can only ever answer for the action it was
        granted against. Any mutation of the action changes the digest (AS-007) and lands
        here as NOT_FOUND rather than silently matching.
        """
        statement = select(Approval).where(Approval.action_digest == action_digest)
        if run_id is not None:
            statement = statement.where(Approval.run_id == run_id)
        statement = statement.order_by(Approval.created_at.desc())

        approval = (await self._session.execute(statement)).scalars().first()
        if approval is None:
            return ApprovalResolution(permitted=False, reason=ApprovalReason.NOT_FOUND)

        # Defence in depth: the query already filtered on digest, but comparing again in
        # constant time means a future change to the lookup cannot quietly weaken the bind.
        if not digests_match(approval.action_digest, action_digest):
            return ApprovalResolution(
                permitted=False,
                reason=ApprovalReason.DIGEST_MISMATCH,
                approval_id=approval.id,
                state=approval.state,
            )

        now = self._clock()

        if approval.state is ApprovalState.DENIED:
            return ApprovalResolution(
                permitted=False,
                reason=ApprovalReason.DENIED,
                approval_id=approval.id,
                approver_principal=approval.approver_principal,
                state=approval.state,
            )

        if approval.state is ApprovalState.EXPIRED or now >= as_aware(approval.expires_at):
            # Expiry is evaluated on read, not only on a timer. A record that lapsed while
            # nothing was watching must not become usable just because no job ran.
            if approval.state is not ApprovalState.EXPIRED:
                approval.state = ApprovalState.EXPIRED
                await self._session.flush()
            return ApprovalResolution(
                permitted=False,
                reason=ApprovalReason.EXPIRED,
                approval_id=approval.id,
                state=ApprovalState.EXPIRED,
            )

        if approval.state is ApprovalState.PENDING:
            return ApprovalResolution(
                permitted=False,
                reason=ApprovalReason.PENDING,
                approval_id=approval.id,
                state=approval.state,
            )

        return ApprovalResolution(
            permitted=True,
            reason=ApprovalReason.APPROVED,
            approval_id=approval.id,
            approver_principal=approval.approver_principal,
            state=approval.state,
        )

    async def expire_lapsed(self) -> int:
        """Mark every lapsed pending approval as expired. Returns how many changed.

        Housekeeping only — :meth:`resolve` already evaluates expiry on read, so a stale
        PENDING row is never usable. This exists so the stored state matches reality for
        anything reading the table directly, such as the approval UI.
        """
        now = self._clock()
        statement = select(Approval).where(
            Approval.state == ApprovalState.PENDING, Approval.expires_at <= now
        )
        lapsed = list((await self._session.execute(statement)).scalars())
        for approval in lapsed:
            approval.state = ApprovalState.EXPIRED
        if lapsed:
            await self._session.flush()
        return len(lapsed)


__all__ = [
    "CONTEXT_DIGEST_DOMAIN",
    "ApprovalError",
    "ApprovalReason",
    "ApprovalResolution",
    "ApprovalService",
    "as_aware",
    "authenticate_operator",
    "compute_context_digest",
]
