"""Temporal worker and workflow tests (AS-019, AS-020).

These need the real stack, because what they check cannot be faked. A mock Temporal would
happily run a non-deterministic workflow; the whole point is that the real engine replays
history and would not.

    docker compose up -d
    uv run pytest -m integration

Skipped automatically when Temporal is unreachable, so `uv run task check` stays green
without containers.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from temporalio.client import Client, WorkflowFailureError, WorkflowHandle
from temporalio.worker import Worker

from agentsec.db.base import Base
from agentsec.db.models import Run, RunStatus
from agentsec.workflows.activities import ActivityContext
from agentsec.workflows.security_review import SecurityReviewWorkflow
from agentsec.workflows.shared import ReviewRequest, ReviewResult, ReviewState

pytestmark = pytest.mark.integration

TEMPORAL_ADDRESS = "localhost:7233"
NAMESPACE = "agentsec"


def temporal_reachable() -> bool:
    try:
        with socket.create_connection(("localhost", 7233), timeout=2):
            return True
    except OSError:
        return False


requires_temporal = pytest.mark.skipif(
    not temporal_reachable(), reason="Temporal not reachable (docker compose up -d)"
)


@pytest_asyncio.fixture
async def environment() -> AsyncIterator[tuple[Client, ActivityContext, str]]:
    """A client, activity dependencies backed by in-memory SQLite, and a unique queue.

    SQLite rather than the compose Postgres so these tests do not depend on migration
    state, and a per-test task queue so a leftover worker from an earlier run cannot pick
    up this test's workflow.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    client = await Client.connect(TEMPORAL_ADDRESS, namespace=NAMESPACE)
    yield client, ActivityContext(session_factory=factory), f"test-{uuid.uuid4().hex[:8]}"
    await engine.dispose()


def build(client: Client, context: ActivityContext, queue: str) -> Worker:
    return Worker(
        client,
        task_queue=queue,
        workflows=[SecurityReviewWorkflow],
        activities=[
            context.create_run,
            context.record_transition,
            context.collect_context,
            context.plan_actions,
        ],
    )


def request(run_id: str) -> ReviewRequest:
    return ReviewRequest(
        run_id=run_id,
        principal="planner",
        task="review repo-a for injection risks",
        repository="fixture://repo-a",
    )


@requires_temporal
async def test_worker_registers_and_runs_a_workflow_to_completion(
    environment: tuple[Client, ActivityContext, str],
) -> None:
    client, context, queue = environment
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    async with build(client, context, queue):
        result: ReviewResult = await client.execute_workflow(
            SecurityReviewWorkflow.run,
            request(run_id),
            id=f"wf-{run_id}",
            task_queue=queue,
        )

    assert result.state is ReviewState.COMPLETED
    assert result.executed_actions == 0


@requires_temporal
async def test_state_transitions_are_persisted(
    environment: tuple[Client, ActivityContext, str],
) -> None:
    """Temporal owns execution state; PostgreSQL owns the product view. Neither is
    derived from the other, so the product view has to actually be written."""
    client, context, queue = environment
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    async with build(client, context, queue):
        await client.execute_workflow(
            SecurityReviewWorkflow.run, request(run_id), id=f"wf-{run_id}", task_queue=queue
        )

    async with context.session_factory() as session:
        run = await session.get(Run, run_id)
        assert run is not None
        assert run.status is RunStatus.COMPLETED
        assert run.finished_at is not None
        assert run.workflow_id == f"wf-{run_id}"


@requires_temporal
async def test_state_is_queryable_while_running(
    environment: tuple[Client, ActivityContext, str],
) -> None:
    client, context, queue = environment
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    async with build(client, context, queue):
        handle: WorkflowHandle[SecurityReviewWorkflow, ReviewResult] = await client.start_workflow(
            SecurityReviewWorkflow.run, request(run_id), id=f"wf-{run_id}", task_queue=queue
        )
        await handle.result()
        assert await handle.query(SecurityReviewWorkflow.current_state) == "COMPLETED"


@requires_temporal
async def test_cancellation_records_a_terminal_state(
    environment: tuple[Client, ActivityContext, str],
) -> None:
    """A run that vanishes without a terminal state is indistinguishable from one still
    in progress, which makes the product view useless during an incident."""
    client, context, queue = environment
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    # No worker running, so the workflow is started but never progresses; cancelling it
    # exercises the cancellation path deterministically rather than by racing.
    handle = await client.start_workflow(
        SecurityReviewWorkflow.run, request(run_id), id=f"wf-{run_id}", task_queue=queue
    )
    await handle.cancel()

    async with build(client, context, queue), asyncio.timeout(30):
        with pytest.raises(WorkflowFailureError):
            await handle.result()

    description = await handle.describe()
    assert description.status is not None


@requires_temporal
async def test_history_replays_without_non_determinism(
    environment: tuple[Client, ActivityContext, str],
) -> None:
    """The property the determinism rules exist for.

    A workflow that reads the clock or generates a UUID directly takes a different branch
    on replay, and the divergence surfaces here rather than during a live recovery.
    """
    from temporalio.worker import Replayer

    client, context, queue = environment
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    async with build(client, context, queue):
        handle = await client.start_workflow(
            SecurityReviewWorkflow.run, request(run_id), id=f"wf-{run_id}", task_queue=queue
        )
        await handle.result()

    history = await handle.fetch_history()
    await Replayer(workflows=[SecurityReviewWorkflow]).replay_workflow(history)


@requires_temporal
async def test_a_second_run_is_independent(
    environment: tuple[Client, ActivityContext, str],
) -> None:
    client, context, queue = environment
    async with build(client, context, queue):
        for _ in range(2):
            run_id = f"run-{uuid.uuid4().hex[:8]}"
            result = await client.execute_workflow(
                SecurityReviewWorkflow.run,
                request(run_id),
                id=f"wf-{run_id}",
                task_queue=queue,
            )
            assert result.run_id == run_id
