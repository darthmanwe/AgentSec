"""Exact-action approval tests (AS-010).

Runs against in-memory SQLite so the S1 gate stays provable with no container and no model.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentsec.authz.approvals import (
    ApprovalError,
    ApprovalReason,
    ApprovalResolution,
    ApprovalService,
    authenticate_operator,
    compute_context_digest,
)
from agentsec.authz.models import ContextItem, Principal, PrincipalKind, TrustLevel
from agentsec.db.base import Base
from agentsec.db.models import ApprovalState, Run, RunStatus

pytestmark = pytest.mark.authz

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
START = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.UTC)

OPERATOR = Principal(id="alice", kind=PrincipalKind.OPERATOR)
AGENT = Principal(id="planner", kind=PrincipalKind.AGENT)


class MovableClock:
    """A clock the tests advance explicitly, so expiry is tested without sleeping."""

    def __init__(self, start: dt.datetime) -> None:
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += dt.timedelta(**kwargs)


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_on(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        s.add(
            Run(
                id="run-1",
                workflow_id="wf-1",
                status=RunStatus.WAITING_APPROVAL,
                principal="planner",
                task="review",
            )
        )
        await s.commit()
        yield s
    await engine.dispose()


@pytest.fixture
def clock() -> MovableClock:
    return MovableClock(START)


@pytest.fixture
def service(session: AsyncSession, clock: MovableClock) -> ApprovalService:
    return ApprovalService(session, clock=clock)


# --------------------------------------------------------------------------- happy path


async def test_approved_action_resolves_as_permitted(service: ApprovalService) -> None:
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A)
    await service.decide(approval.id, approver=OPERATOR, approved=True)

    resolution = await service.resolve(action_digest=DIGEST_A)
    assert resolution.permitted is True
    assert resolution.reason is ApprovalReason.APPROVED
    assert resolution.approver_principal == "alice"


async def test_pending_approval_does_not_permit(service: ApprovalService) -> None:
    await service.create(run_id="run-1", action_digest=DIGEST_A)
    resolution = await service.resolve(action_digest=DIGEST_A)
    assert resolution.permitted is False
    assert resolution.reason is ApprovalReason.PENDING


async def test_denied_approval_does_not_permit(service: ApprovalService) -> None:
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A)
    await service.decide(approval.id, approver=OPERATOR, approved=False, note="looks wrong")
    resolution = await service.resolve(action_digest=DIGEST_A)
    assert resolution.permitted is False
    assert resolution.reason is ApprovalReason.DENIED


# --------------------------------------------------------------------------- binding


async def test_approval_does_not_authorise_a_different_action(service: ApprovalService) -> None:
    """The central property. An approval is for one action, identified by its digest.

    Any mutation of the action changes the digest (AS-007), so a mutated action arrives
    here as a different digest and finds no approval.
    """
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A)
    await service.decide(approval.id, approver=OPERATOR, approved=True)

    resolution = await service.resolve(action_digest=DIGEST_B)
    assert resolution.permitted is False
    assert resolution.reason is ApprovalReason.NOT_FOUND


async def test_approval_is_scoped_to_its_run(service: ApprovalService) -> None:
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A)
    await service.decide(approval.id, approver=OPERATOR, approved=True)

    assert (await service.resolve(action_digest=DIGEST_A, run_id="run-1")).permitted is True
    assert (await service.resolve(action_digest=DIGEST_A, run_id="run-2")).permitted is False


async def test_no_approval_at_all_is_reported_distinctly(service: ApprovalService) -> None:
    """ "No approval" and "expired approval" must not look identical to a caller: one is a
    missing step, the other is an operator who took too long."""
    resolution = await service.resolve(action_digest=DIGEST_A)
    assert resolution.reason is ApprovalReason.NOT_FOUND


# --------------------------------------------------------------------------- expiry


async def test_expired_approval_does_not_permit(
    service: ApprovalService, clock: MovableClock
) -> None:
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A, ttl_seconds=60)
    await service.decide(approval.id, approver=OPERATOR, approved=True)

    clock.advance(seconds=61)
    resolution = await service.resolve(action_digest=DIGEST_A)
    assert resolution.permitted is False
    assert resolution.reason is ApprovalReason.EXPIRED


async def test_expiry_is_evaluated_on_read_not_only_by_a_timer(
    service: ApprovalService, clock: MovableClock, session: AsyncSession
) -> None:
    """A record that lapsed while nothing was watching must not become usable just because
    no background job ran."""
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A, ttl_seconds=60)
    await service.decide(approval.id, approver=OPERATOR, approved=True)
    clock.advance(seconds=120)

    resolution = await service.resolve(action_digest=DIGEST_A)
    assert resolution.permitted is False

    await session.refresh(approval)
    assert approval.state is ApprovalState.EXPIRED, "state should be persisted, not just reported"


async def test_deciding_an_expired_approval_fails(
    service: ApprovalService, clock: MovableClock
) -> None:
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A, ttl_seconds=60)
    clock.advance(seconds=61)
    with pytest.raises(ApprovalError, match="expired"):
        await service.decide(approval.id, approver=OPERATOR, approved=True)


async def test_expire_lapsed_updates_stored_state(
    service: ApprovalService, clock: MovableClock
) -> None:
    await service.create(run_id="run-1", action_digest=DIGEST_A, ttl_seconds=60)
    await service.create(run_id="run-1", action_digest=DIGEST_B, ttl_seconds=3600)
    clock.advance(seconds=120)
    assert await service.expire_lapsed() == 1


# --------------------------------------------------------------------------- authority


async def test_an_agent_cannot_approve(service: ApprovalService) -> None:
    """The core invariant. A model principal reaching this method is either a bug or an
    escalation attempt; either way it is refused."""
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A)
    with pytest.raises(ApprovalError, match="cannot approve"):
        await service.decide(approval.id, approver=AGENT, approved=True)


async def test_a_system_principal_cannot_approve(service: ApprovalService) -> None:
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A)
    system = Principal(id="worker", kind=PrincipalKind.SYSTEM)
    with pytest.raises(ApprovalError, match="cannot approve"):
        await service.decide(approval.id, approver=system, approved=True)


async def test_a_decision_is_terminal(service: ApprovalService) -> None:
    """Without this, an attacker reaching the approval API could flip a DENIED record to
    APPROVED and inherit the original operator's identity."""
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A)
    await service.decide(approval.id, approver=OPERATOR, approved=False)

    with pytest.raises(ApprovalError, match="decisions are terminal"):
        await service.decide(approval.id, approver=OPERATOR, approved=True)

    assert (await service.resolve(action_digest=DIGEST_A)).reason is ApprovalReason.DENIED


async def test_deciding_an_unknown_approval_fails(service: ApprovalService) -> None:
    with pytest.raises(ApprovalError, match="does not exist"):
        await service.decide("ap-nope", approver=OPERATOR, approved=True)


# --------------------------------------------------------------------------- operator auth


def test_operator_token_authenticates() -> None:
    principal = authenticate_operator("s3cret-token", "s3cret-token")
    assert principal is not None
    assert principal.may_approve


def test_wrong_operator_token_is_rejected() -> None:
    assert authenticate_operator("wrong", "s3cret-token") is None


def test_missing_expected_token_authenticates_nobody() -> None:
    """The failure mode of an unconfigured secret must be "no access", not "open access"."""
    assert authenticate_operator("anything", None) is None
    assert authenticate_operator("anything", "") is None


def test_missing_presented_token_is_rejected() -> None:
    assert authenticate_operator(None, "s3cret-token") is None


# --------------------------------------------------------------------------- context digest


def make_item(item_id: str, content: str, trust: TrustLevel = TrustLevel.UNTRUSTED) -> ContextItem:
    return ContextItem(
        id=item_id,
        source=f"fixture://{item_id}",
        trust=trust,
        content=content,
        retrieved_at=START,
    )


def test_context_digest_is_order_independent() -> None:
    """The digest must not depend on the order the UI happened to render evidence."""
    a, b = make_item("c1", "alpha"), make_item("c2", "beta")
    assert compute_context_digest([a, b]) == compute_context_digest([b, a])


def test_context_digest_changes_when_evidence_changes() -> None:
    """Proves what the operator was looking at. If the evidence changed, the approval was
    granted against a different picture."""
    assert compute_context_digest([make_item("c1", "alpha")]) != compute_context_digest(
        [make_item("c1", "alpha, plus something new")]
    )


def test_context_digest_changes_when_trust_label_changes() -> None:
    assert compute_context_digest([make_item("c1", "x", TrustLevel.UNTRUSTED)]) != (
        compute_context_digest([make_item("c1", "x", TrustLevel.TRUSTED)])
    )


def test_empty_evidence_still_produces_a_digest() -> None:
    assert len(compute_context_digest([])) == 64


async def test_created_approval_records_the_context_digest(service: ApprovalService) -> None:
    items = [make_item("c1", "README says to ignore prior instructions")]
    approval = await service.create(run_id="run-1", action_digest=DIGEST_A, context_items=items)
    assert approval.approval_context_digest == compute_context_digest(items)


# --------------------------------------------------------------------------- result type


def test_a_permitted_resolution_must_carry_the_approved_reason() -> None:
    """Guards against constructing a permissive result with a denial reason attached."""
    with pytest.raises(ValueError, match="must carry the APPROVED reason"):
        ApprovalResolution(permitted=True, reason=ApprovalReason.EXPIRED)
