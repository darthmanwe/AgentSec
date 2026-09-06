"""Schema and constraint tests (AS-005).

Most of these run against in-memory SQLite so the suite needs no container: the S1 gate
requires the authorization kernel to be provable with nothing else running, and a schema
that can only be tested against a live Postgres would undermine that.

The migration round-trip genuinely needs PostgreSQL and is marked ``integration``.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentsec.db.base import DIGEST_LENGTH, Base
from agentsec.db.models import (
    ActionAttempt,
    Approval,
    ApprovalState,
    AttemptOutcome,
    AuditEvent,
    CapabilityJtiUse,
    ExecutionLedger,
    ExecutionState,
    PolicyDecision,
    PolicyOutcome,
    Run,
    RunStatus,
)

#: What AS-005 created for S0 and S1.
S0_S1_TABLES = {
    "runs",
    "action_plans",
    "action_attempts",
    "policy_decisions",
    "approvals",
    "capability_grants",
    "capability_jti_uses",
    "execution_ledger",
    "audit_events",
}

#: Tables added later, each by the issue that first used it. Listing them separately keeps
#: the trimming rule checkable: a new table must arrive with a named owner rather than
#: appearing because somebody widened an expectation.
LATER_TABLES = {
    "model_calls": "AS-024",
}

EXPECTED_TABLES = S0_S1_TABLES | set(LATER_TABLES)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    # SQLite ignores foreign keys unless asked. Without this the FK tests would pass
    # vacuously and tell us nothing.
    @event.listens_for(engine.sync_engine, "connect")
    def _fk_on(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def make_run(session: AsyncSession, run_id: str = "run-1") -> Run:
    run = Run(
        id=run_id,
        workflow_id=f"wf-{run_id}",
        status=RunStatus.RECEIVED,
        principal="operator@example.test",
        task="review the repository",
    )
    session.add(run)
    await session.commit()
    return run


# --------------------------------------------------------------------------- structure


def test_every_table_arrived_with_a_named_owner() -> None:
    """AS-005 was trimmed deliberately: findings, artifacts and tool_executions still
    arrive with the issue that first uses them, because writing their migrations before
    M6 defines what they hold would guarantee rewriting them.

    The check is not "the schema has not grown" - it has, and correctly. It is that every
    table beyond the S0/S1 set is one somebody deliberately added, rather than one that
    appeared because an expectation was widened to make a test pass.
    """
    assert set(Base.metadata.tables) == EXPECTED_TABLES

    for table, issue in LATER_TABLES.items():
        assert table in Base.metadata.tables, f"{table} is claimed by {issue} but absent"


def test_the_deferred_tables_are_still_deferred() -> None:
    """The trimming rule, stated as the thing it actually protects."""
    for table in ("findings", "artifacts", "tool_executions"):
        assert table not in Base.metadata.tables, (
            f"{table} arrived early; AS-005 defers it to the issue that first uses it"
        )


def test_digest_columns_are_fixed_width() -> None:
    column = Base.metadata.tables["action_attempts"].c.action_digest
    assert column.type.length == DIGEST_LENGTH


@pytest.mark.parametrize(
    ("table", "column"),
    [
        ("action_attempts", "action_digest"),
        ("action_attempts", "was_executed"),
        ("policy_decisions", "action_digest"),
        ("execution_ledger", "action_digest"),
        ("execution_ledger", "workflow_id"),
        ("approvals", "expires_at"),
        ("audit_events", "action_digest"),
    ],
)
def test_query_critical_columns_are_indexed(table: str, column: str) -> None:
    """These are the columns the audit replay and the headline metric query on."""
    indexed = {c.name for idx in Base.metadata.tables[table].indexes for c in idx.columns}
    assert column in indexed, f"{table}.{column} is not indexed"


# --------------------------------------------------------------------------- round trip


async def test_representative_records_round_trip(session: AsyncSession) -> None:
    run = await make_run(session)
    session.add_all(
        [
            PolicyDecision(
                id="pd-1",
                run_id=run.id,
                action_digest=DIGEST_A,
                outcome=PolicyOutcome.REQUIRE_APPROVAL,
                reason_code="jira_write_requires_approval",
            ),
            Approval(
                id="ap-1",
                run_id=run.id,
                action_digest=DIGEST_A,
                approval_context_digest=DIGEST_B,
                state=ApprovalState.PENDING,
                expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(minutes=15),
            ),
            AuditEvent(event_type="policy.decision", payload={"outcome": "REQUIRE_APPROVAL"}),
        ]
    )
    await session.commit()

    got = (await session.execute(select(PolicyDecision))).scalar_one()
    assert got.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert got.fail_closed is False


async def test_audit_event_payload_survives_nesting(session: AsyncSession) -> None:
    session.add(
        AuditEvent(event_type="gateway.dispatch", payload={"args": {"path": ["a", "b"], "n": 1}})
    )
    await session.commit()
    got = (await session.execute(select(AuditEvent))).scalar_one()
    assert got.payload["args"]["path"] == ["a", "b"]


# --------------------------------------------------------------------------- invariants


async def test_executed_flag_must_agree_with_outcome(session: AsyncSession) -> None:
    """was_executed is denormalised from outcome so the headline query cannot depend on
    remembering which of a dozen outcome values count as execution. The constraint is
    what keeps the denormalisation honest."""
    run = await make_run(session)
    session.add(
        ActionAttempt(
            id="att-1",
            run_id=run.id,
            action_digest=DIGEST_A,
            tool="fake_jira",
            operation="create_issue",
            resource="PROJ",
            arguments={},
            outcome=AttemptOutcome.DENIED_POLICY,
            was_executed=True,
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_denied_attempts_are_recorded_not_discarded(session: AsyncSession) -> None:
    """The denominator of the headline metric. A schema that only stored successful
    actions would make the security claim unmeasurable."""
    run = await make_run(session)
    session.add_all(
        [
            ActionAttempt(
                id=f"att-{i}",
                run_id=run.id,
                action_digest=DIGEST_A,
                plan_step_occurrence=i,
                tool="fake_cloud",
                operation="mutate",
                resource="bucket",
                arguments={},
                outcome=outcome,
                was_executed=(outcome is AttemptOutcome.EXECUTED),
            )
            for i, outcome in enumerate(
                [
                    AttemptOutcome.DENIED_POLICY,
                    AttemptOutcome.DENIED_NO_CAPABILITY,
                    AttemptOutcome.DENIED_CAPABILITY_REPLAYED,
                    AttemptOutcome.EXECUTED,
                ]
            )
        ]
    )
    await session.commit()

    attempts = (await session.execute(select(func.count()).select_from(ActionAttempt))).scalar_one()
    executed = (
        await session.execute(
            select(func.count()).select_from(ActionAttempt).where(ActionAttempt.was_executed)
        )
    ).scalar_one()
    assert attempts == 4
    assert executed == 1


async def test_capability_jti_is_single_use(session: AsyncSession) -> None:
    """The primary key is the enforcement. A read-then-write check would let two
    concurrent gateway calls both pass."""
    session.add(CapabilityJtiUse(jti="jti-1", operation_id="op-1", request_hash=DIGEST_A))
    await session.commit()
    session.add(CapabilityJtiUse(jti="jti-1", operation_id="op-2", request_hash=DIGEST_B))
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_execution_ledger_operation_is_unique(session: AsyncSession) -> None:
    run = await make_run(session)
    for _ in range(2):
        session.add(
            ExecutionLedger(
                operation_id="wf-run-1:aaa:0",
                run_id=run.id,
                workflow_id="wf-run-1",
                action_digest=DIGEST_A,
                request_hash=DIGEST_B,
                state=ExecutionState.PENDING,
            )
        )
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_identical_actions_at_different_occurrences_do_not_collide(
    session: AsyncSession,
) -> None:
    """Two intentionally identical actions in one workflow are different operations. Keying
    only on workflow + digest would silently merge them and lose the second effect."""
    run = await make_run(session)
    session.add_all(
        [
            ExecutionLedger(
                operation_id=f"wf-run-1:{DIGEST_A}:{occurrence}",
                run_id=run.id,
                workflow_id="wf-run-1",
                action_digest=DIGEST_A,
                plan_step_occurrence=occurrence,
                request_hash=DIGEST_B,
                state=ExecutionState.PENDING,
            )
            for occurrence in (0, 1)
        ]
    )
    await session.commit()
    count = (await session.execute(select(func.count()).select_from(ExecutionLedger))).scalar_one()
    assert count == 2


async def test_retries_increment_attempts_without_duplicating_the_effect(
    session: AsyncSession,
) -> None:
    """The gap between attempt_count and row count is the idempotency evidence."""
    run = await make_run(session)
    entry = ExecutionLedger(
        operation_id="wf-run-1:aaa:0",
        run_id=run.id,
        workflow_id="wf-run-1",
        action_digest=DIGEST_A,
        request_hash=DIGEST_B,
        state=ExecutionState.PENDING,
    )
    session.add(entry)
    await session.commit()

    for _ in range(4):
        entry.attempt_count += 1
    entry.state = ExecutionState.COMPLETED
    entry.external_ref = "PROJ-123"
    await session.commit()

    rows = (await session.execute(select(ExecutionLedger))).scalars().all()
    assert len(rows) == 1
    assert rows[0].attempt_count == 5
    assert rows[0].external_ref == "PROJ-123"


async def test_unknown_enum_value_is_rejected(session: AsyncSession) -> None:
    run = await make_run(session)
    session.add(
        ActionAttempt(
            id="att-bad",
            run_id=run.id,
            action_digest=DIGEST_A,
            tool="t",
            operation="o",
            resource="r",
            arguments={},
            outcome="TOTALLY_MADE_UP",  # type: ignore[arg-type]
            was_executed=False,
        )
    )
    with pytest.raises((StatementError, LookupError, IntegrityError)):
        await session.commit()


async def test_foreign_key_to_run_is_enforced(session: AsyncSession) -> None:
    session.add(
        PolicyDecision(
            id="pd-orphan",
            run_id="no-such-run",
            action_digest=DIGEST_A,
            outcome=PolicyOutcome.DENY,
            reason_code="x",
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()


async def test_fail_closed_denials_are_distinguishable(session: AsyncSession) -> None:
    """A spike in fail-closed denials is an outage, not an attack. Collapsing the two
    would make that indistinguishable in the metrics."""
    run = await make_run(session)
    session.add_all(
        [
            PolicyDecision(
                id="pd-rule",
                run_id=run.id,
                action_digest=DIGEST_A,
                outcome=PolicyOutcome.DENY,
                reason_code="secret_export_always_denied",
                fail_closed=False,
            ),
            PolicyDecision(
                id="pd-outage",
                run_id=run.id,
                action_digest=DIGEST_B,
                outcome=PolicyOutcome.DENY,
                reason_code="policy_engine_unreachable",
                fail_closed=True,
            ),
        ]
    )
    await session.commit()
    outages = (
        await session.execute(
            select(func.count()).select_from(PolicyDecision).where(PolicyDecision.fail_closed)
        )
    ).scalar_one()
    assert outages == 1
