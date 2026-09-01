"""Execution ledger tests (AS-022).

The test that matters most is ``test_a_retry_of_a_spent_capability_does_not_deadlock``.
It reproduces the exact conflict a review found in the rev-1 plan: single-use capabilities
and durable retries are individually correct and, in the wrong order, jointly broken.

Everything else here is about counting effects. A ledger that reported success while
letting a side effect happen twice would pass any test that only checked return values.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentsec.authz.capabilities import (
    CapabilityMinter,
    CapabilityRedeemer,
    CapabilityVerifier,
    ExpectedBinding,
    compute_request_hash,
)
from agentsec.authz.keys import SigningKey, VerificationKeyring
from agentsec.db.base import Base
from agentsec.db.models import ExecutionState, Run, RunStatus
from agentsec.gateway.ledger import (
    ExecutionLedgerService,
    ReconciliationRequiredError,
    operation_id,
)

pytestmark = pytest.mark.authz

DIGEST = "a" * 64
REQUEST_HASH = compute_request_hash({"summary": "Fix SQLi"})


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        s.add(
            Run(
                id="run-1",
                workflow_id="wf-1",
                status=RunStatus.EXECUTING,
                principal="planner",
                task="review",
            )
        )
        await s.commit()
        yield s
    await engine.dispose()


@pytest.fixture
def ledger(session: AsyncSession) -> ExecutionLedgerService:
    return ExecutionLedgerService(session)


async def claim(
    ledger: ExecutionLedgerService, operation: str, request_hash: str = REQUEST_HASH
) -> object:
    return await ledger.begin(
        operation=operation,
        run_id="run-1",
        workflow_id="wf-1",
        action_digest=DIGEST,
        request_hash=request_hash,
    )


# --------------------------------------------------------------------------- identity


def test_operation_id_includes_the_occurrence_ordinal() -> None:
    """Two intentionally identical actions in one workflow are different operations.
    Keying on workflow plus digest alone would merge them and lose the second effect."""
    first = operation_id("wf-1", DIGEST, 0)
    second = operation_id("wf-1", DIGEST, 1)
    assert first != second


def test_operation_id_is_scoped_to_the_workflow() -> None:
    assert operation_id("wf-1", DIGEST) != operation_id("wf-2", DIGEST)


def test_operation_id_is_scoped_to_the_action() -> None:
    assert operation_id("wf-1", "a" * 64) != operation_id("wf-1", "b" * 64)


# --------------------------------------------------------------------------- lifecycle


async def test_a_first_attempt_proceeds(ledger: ExecutionLedgerService) -> None:
    decision = await claim(ledger, "op-1")
    assert decision.proceed is True  # type: ignore[attr-defined]
    assert decision.replayed is False  # type: ignore[attr-defined]


async def test_a_completed_operation_returns_its_cached_result(
    ledger: ExecutionLedgerService,
) -> None:
    await claim(ledger, "op-1")
    await ledger.complete("op-1", {"key": "PROJ-42"}, external_ref="PROJ-42")

    decision = await claim(ledger, "op-1")
    assert decision.proceed is False  # type: ignore[attr-defined]
    assert decision.replayed is True  # type: ignore[attr-defined]
    assert decision.cached_result == {"key": "PROJ-42"}  # type: ignore[attr-defined]


async def test_a_failed_operation_may_be_retried(ledger: ExecutionLedgerService) -> None:
    """A recorded failure means the backend was reached and refused. The effect did not
    happen, so retrying is legitimate."""
    await claim(ledger, "op-1")
    await ledger.fail("op-1", "backend returned 503")

    decision = await claim(ledger, "op-1")
    assert decision.proceed is True  # type: ignore[attr-defined]


async def test_repeated_attempts_produce_one_logical_effect(
    ledger: ExecutionLedgerService,
) -> None:
    """The claim, measured. Attempts climb; effects do not."""
    await claim(ledger, "op-1")
    await ledger.complete("op-1", {"key": "PROJ-42"})

    for _ in range(5):
        decision = await claim(ledger, "op-1")
        assert decision.proceed is False  # type: ignore[attr-defined]

    assert await ledger.logical_effects("wf-1") == 1
    assert await ledger.total_attempts("wf-1") == 1


async def test_two_distinct_operations_both_execute(ledger: ExecutionLedgerService) -> None:
    for index in range(2):
        operation = operation_id("wf-1", DIGEST, index)
        await claim(ledger, operation)
        await ledger.complete(operation, {"index": index})

    assert await ledger.logical_effects("wf-1") == 2


# --------------------------------------------------------------------------- safety


async def test_a_different_request_body_cannot_reuse_an_operation_id(
    ledger: ExecutionLedgerService,
) -> None:
    """Either a bug in id construction or an attempt to smuggle different arguments under
    a completed operation's identity. Neither is something to proceed through."""
    await claim(ledger, "op-1")
    await ledger.complete("op-1", {"key": "PROJ-42"})

    with pytest.raises(ValueError, match="different request"):
        await claim(ledger, "op-1", request_hash="f" * 64)


async def test_an_operation_stuck_pending_demands_reconciliation(
    session: AsyncSession,
) -> None:
    """A previous attempt reached the backend and never recorded an outcome, so whether
    the effect happened is genuinely unknown. Retrying blindly could duplicate it; failing
    silently could lose it. Stopping is the honest answer."""
    ledger = ExecutionLedgerService(session, max_pending_attempts=2)
    await claim(ledger, "op-1")
    await claim(ledger, "op-1")

    with pytest.raises(ReconciliationRequiredError):
        await claim(ledger, "op-1")


async def test_completing_an_unclaimed_operation_is_an_error(
    ledger: ExecutionLedgerService,
) -> None:
    with pytest.raises(ValueError, match="never claimed"):
        await ledger.complete("op-never", {"x": 1})


async def test_external_ref_is_recorded_for_reconciliation(
    ledger: ExecutionLedgerService, session: AsyncSession
) -> None:
    """Without the backend's own identifier, the only way to answer "did this land?" after
    a lost acknowledgement is to look and guess."""
    from agentsec.db.models import ExecutionLedger as Row

    await claim(ledger, "op-1")
    await ledger.complete("op-1", {"key": "PROJ-42"}, external_ref="PROJ-42")

    entry = await session.get(Row, "op-1")
    assert entry is not None
    assert entry.external_ref == "PROJ-42"
    assert entry.state is ExecutionState.COMPLETED
    assert entry.completed_at is not None


# ------------------------------------------------- the conflict this exists to resolve


async def test_a_retry_of_a_spent_capability_does_not_deadlock(
    session: AsyncSession,
) -> None:
    """The reason the ledger is consulted *before* redemption.

    Single-use capabilities and durable retries are each correct in isolation and, in the
    wrong order, jointly broken: a retry whose response was lost presents a capability
    that has already been redeemed, is denied, and the workflow can never finish. That
    failure appears only under exactly the fault the durable execution story is meant to
    survive.

    This test does it in both orders and shows the difference.
    """
    key = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())
    verifier = CapabilityVerifier(VerificationKeyring.of(key.kid, key.public_key))
    redeemer = CapabilityRedeemer(session)
    ledger = ExecutionLedgerService(session)

    token = CapabilityMinter(key).mint(
        subject="planner",
        audience="agentsec-gateway",
        environment="local",
        workflow_id="wf-1",
        action_digest=DIGEST,
        request_hash=REQUEST_HASH,
        tool="fake_jira",
        resource="jira://PROJ",
        scopes=("jira:write",),
        ttl_seconds=60,
    )
    binding = ExpectedBinding(
        subject="planner",
        audience="agentsec-gateway",
        environment="local",
        workflow_id="wf-1",
        action_digest=DIGEST,
        request_hash=REQUEST_HASH,
        tool="fake_jira",
        resource="jira://PROJ",
        required_scopes=("jira:write",),
    )
    operation = operation_id("wf-1", DIGEST, 0)

    # --- first attempt: ledger, then redemption, then the effect
    first = await ledger.begin(
        operation=operation,
        run_id="run-1",
        workflow_id="wf-1",
        action_digest=DIGEST,
        request_hash=REQUEST_HASH,
    )
    assert first.proceed is True

    verified = verifier.verify(token, binding)
    assert verified.ok and verified.claims is not None
    assert await redeemer.redeem(verified.claims, operation_id=operation) is True
    await ledger.complete(operation, {"key": "PROJ-42"}, external_ref="PROJ-42")

    # --- the retry: response was lost, Temporal re-runs the activity with the same token
    retry = await ledger.begin(
        operation=operation,
        run_id="run-1",
        workflow_id="wf-1",
        action_digest=DIGEST,
        request_hash=REQUEST_HASH,
    )
    assert retry.proceed is False, "the ledger must short-circuit before redemption"
    assert retry.cached_result == {"key": "PROJ-42"}

    # And the proof that the ordering is load-bearing: had the retry reached redemption,
    # it would have been denied and the workflow could never have completed.
    assert await redeemer.redeem(verified.claims, operation_id=operation) is False

    assert await ledger.logical_effects("wf-1") == 1
