"""Operator CLI tests (AS-021).

The CLI is where a human's authority enters the system, so these tests are less about
argument parsing than about what an unauthenticated caller cannot do. Every negative case
here asserts the *stored state*, not just the exit code: a command that returns failure
while having already written the decision would pass a weaker test and be a critical bug.

No Temporal needed. The notification is best-effort by design, and one test proves that by
pointing the CLI at an address nothing is listening on.
"""

from __future__ import annotations

import datetime as dt
import pathlib
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from agentsec.authz.approvals import ApprovalService
from agentsec.cli.main import EXIT_DENIED_AUTH, EXIT_ERROR, EXIT_OK, run
from agentsec.config import Settings
from agentsec.db.base import Base
from agentsec.db.models import Approval, ApprovalState, Run, RunStatus

pytestmark = pytest.mark.authz

TOKEN = "operator-token-for-tests"
DIGEST = "c" * 64


@pytest_asyncio.fixture
async def database(tmp_path: pathlib.Path) -> AsyncIterator[str]:
    """A file-backed SQLite database.

    File rather than ``:memory:`` because each CLI invocation opens its own engine, and an
    in-memory database would give every command a private, empty one - the tests would
    pass while testing nothing.
    """
    url = f"sqlite+aiosqlite:///{(tmp_path / 'agentsec.db').as_posix()}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add(
            Run(
                id="run-1",
                workflow_id="wf-1",
                status=RunStatus.WAITING_APPROVAL,
                principal="planner",
                task="review",
            )
        )
        await session.commit()
    await engine.dispose()
    yield url


def settings_for(
    url: str, *, token: str | None = TOKEN, temporal: str = "localhost:7233"
) -> Settings:
    return Settings(
        database_url=SecretStr(url),
        operator_token=SecretStr(token) if token is not None else None,
        temporal_address=temporal,
    )


async def open_approval(url: str, *, ttl_seconds: int = 900, digest: str = DIGEST) -> str:
    engine = create_async_engine(url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        approval = await ApprovalService(session).create(
            run_id="run-1", action_digest=digest, ttl_seconds=ttl_seconds
        )
        approval_id = approval.id
        await session.commit()
    await engine.dispose()
    return approval_id


async def read_approval(url: str, approval_id: str) -> Approval:
    engine = create_async_engine(url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        approval = await session.get(Approval, approval_id)
        assert approval is not None
        # Detach before the engine goes away so assertions read the loaded values.
        session.expunge(approval)
    await engine.dispose()
    return approval


# --------------------------------------------------------------------- authenticated


async def test_approving_records_the_deciding_operator(database: str) -> None:
    approval_id = await open_approval(database)

    outcome = await run(
        ["approve", approval_id, "--token", TOKEN, "--operator-id", "kutlu", "--no-notify"],
        settings_for(database),
    )

    assert outcome.code == EXIT_OK
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.APPROVED
    assert stored.approver_principal == "kutlu"
    assert stored.decided_at is not None


async def test_denying_records_a_decision_rather_than_deleting_the_record(database: str) -> None:
    """A denial is evidence. Removing the row would erase the fact that something was
    proposed and refused, which is precisely the measurement this project produces."""
    approval_id = await open_approval(database)

    outcome = await run(
        ["deny", approval_id, "--token", TOKEN, "--note", "not this repo", "--no-notify"],
        settings_for(database),
    )

    assert outcome.code == EXIT_OK
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.DENIED
    assert stored.decision_note == "not this repo"


# --------------------------------------------------------------------- rejected


async def test_a_wrong_token_decides_nothing(database: str) -> None:
    approval_id = await open_approval(database)

    outcome = await run(
        ["approve", approval_id, "--token", "not-the-token", "--no-notify"],
        settings_for(database),
    )

    assert outcome.code == EXIT_DENIED_AUTH
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.PENDING, "a rejected caller must leave no decision"


async def test_an_unconfigured_deployment_authenticates_nobody(database: str) -> None:
    """The failure mode of a missing secret must be "no access", not "open access".

    A shared-token check written the obvious way compares ``None`` to ``None`` and lets
    everyone in on a deployment where the token was never set.
    """
    approval_id = await open_approval(database)

    outcome = await run(
        ["approve", approval_id, "--token", "anything at all", "--no-notify"],
        settings_for(database, token=None),
    )

    assert outcome.code == EXIT_DENIED_AUTH
    assert "not configured" in outcome.lines[0]
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.PENDING


async def test_no_token_at_all_decides_nothing(database: str) -> None:
    approval_id = await open_approval(database)
    outcome = await run(["approve", approval_id, "--no-notify"], settings_for(database))
    assert outcome.code == EXIT_DENIED_AUTH
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.PENDING


async def test_a_decision_cannot_be_reversed(database: str) -> None:
    """Decisions are terminal. Without that, anyone reaching this command could flip a
    denial to an approval and inherit the original operator's identity."""
    approval_id = await open_approval(database)
    await run(["deny", approval_id, "--token", TOKEN, "--no-notify"], settings_for(database))

    outcome = await run(
        ["approve", approval_id, "--token", TOKEN, "--no-notify"], settings_for(database)
    )

    assert outcome.code == EXIT_ERROR
    assert "terminal" in outcome.lines[0]
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.DENIED


async def test_an_expired_approval_cannot_be_decided(database: str) -> None:
    approval_id = await open_approval(database, ttl_seconds=-1)

    outcome = await run(
        ["approve", approval_id, "--token", TOKEN, "--no-notify"], settings_for(database)
    )

    assert outcome.code == EXIT_ERROR
    assert "expired" in outcome.lines[0]
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.EXPIRED


async def test_deciding_a_nonexistent_approval_says_so(database: str) -> None:
    outcome = await run(
        ["approve", "ap-does-not-exist", "--token", TOKEN, "--no-notify"], settings_for(database)
    )
    assert outcome.code == EXIT_ERROR
    assert "does not exist" in outcome.lines[0]


# --------------------------------------------------------------------- notification


async def test_an_unreachable_workflow_does_not_undo_the_decision(database: str) -> None:
    """The notification is an optimisation, not the mechanism.

    The decision is durable in the database before Temporal is contacted at all; a run
    whose notification is lost picks the decision up on its next poll. Treating a
    transport failure as a failed approval would make the human-in-the-loop gate depend
    on the availability of a component that has no say in the decision.
    """
    approval_id = await open_approval(database)

    outcome = await run(
        ["approve", approval_id, "--token", TOKEN],
        # Port 1 is reserved and nothing listens there, so the connection fails fast.
        settings_for(database, temporal="localhost:1"),
    )

    assert outcome.code == EXIT_OK
    assert any("not notified" in line for line in outcome.lines)
    stored = await read_approval(database, approval_id)
    assert stored.state is ApprovalState.APPROVED


# --------------------------------------------------------------------- listing


async def test_list_shows_pending_approvals_without_a_token(database: str) -> None:
    """Seeing that a decision is outstanding is not the authority to make it. Requiring a
    credential to look is how an approval queue ends up unattended."""
    approval_id = await open_approval(database)

    outcome = await run(["list"], settings_for(database))

    assert outcome.code == EXIT_OK
    assert any(approval_id in line for line in outcome.lines)


async def test_list_hides_decided_approvals_unless_asked(database: str) -> None:
    approval_id = await open_approval(database)
    await run(["deny", approval_id, "--token", TOKEN, "--no-notify"], settings_for(database))

    default = await run(["list"], settings_for(database))
    everything = await run(["list", "--all"], settings_for(database))

    assert not any(approval_id in line for line in default.lines)
    assert any(approval_id in line for line in everything.lines)


async def test_list_reports_remaining_time(database: str) -> None:
    await open_approval(database, ttl_seconds=600)
    outcome = await run(["list"], settings_for(database))
    assert any("9m" in line or "10m" in line for line in outcome.lines)


async def test_list_marks_a_lapsed_approval(database: str) -> None:
    await open_approval(database, ttl_seconds=-5)
    outcome = await run(["list"], settings_for(database))
    assert any("lapsed" in line for line in outcome.lines)


async def test_list_can_filter_to_one_run(database: str) -> None:
    approval_id = await open_approval(database)
    outcome = await run(["list", "--run", "run-does-not-exist"], settings_for(database))
    assert outcome.lines == ("no approvals match",)

    scoped = await run(["list", "--run", "run-1"], settings_for(database))
    assert any(approval_id in line for line in scoped.lines)


async def test_expiry_display_handles_a_naive_stored_timestamp(database: str) -> None:
    """SQLite hands timestamps back naive; PostgreSQL returns them aware. Formatting the
    remaining time subtracts one from the other, which raises if the mismatch is not
    handled - a crash that would appear only against SQLite, or only against Postgres,
    depending on which side of the subtraction was naive."""
    approval_id = await open_approval(database, ttl_seconds=300)
    stored = await read_approval(database, approval_id)
    assert stored.expires_at.tzinfo is None or stored.expires_at.tzinfo is dt.UTC

    outcome = await run(["list"], settings_for(database))
    assert outcome.code == EXIT_OK
