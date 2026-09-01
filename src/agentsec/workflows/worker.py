"""Temporal worker bootstrap (AS-019).

Connects, registers the workflow and its activities, and shuts down cleanly. Clean
shutdown matters more than it sounds: a worker killed mid-activity leaves the workflow
task to time out and retry, and while Temporal handles that correctly, it turns an
ordinary deploy into a recovery event that shows up in the failure-injection metrics
(AS-023) as noise indistinguishable from a real fault.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import Sequence
from dataclasses import dataclass
from types import FrameType
from typing import Any

from temporalio.client import Client
from temporalio.worker import Worker

from agentsec.config import Settings, load_settings
from agentsec.db.session import create_engine, create_session_factory
from agentsec.log import configure_logging, get_logger
from agentsec.workflows.activities import ActivityContext
from agentsec.workflows.security_review import SecurityReviewWorkflow
from agentsec.workflows.shared import TASK_QUEUE

log = get_logger("agentsec.workflows.worker")

WORKFLOWS: Sequence[type] = [SecurityReviewWorkflow]


@dataclass
class WorkerHandle:
    """A running worker plus the resources it owns."""

    worker: Worker
    client: Client
    _closers: list[Any]

    async def aclose(self) -> None:
        for closer in reversed(self._closers):
            with contextlib.suppress(Exception):
                await closer()


async def connect(settings: Settings, namespace: str = "agentsec") -> Client:
    return await Client.connect(settings.temporal_address, namespace=namespace)


async def build_worker(
    settings: Settings | None = None,
    *,
    client: Client | None = None,
    task_queue: str | None = None,
) -> WorkerHandle:
    """Assemble a worker with its activity dependencies bound.

    Activities are methods on an ``ActivityContext`` holding a session factory, so the
    worker owns the database connection and workflow code never sees one.
    """
    resolved = settings or load_settings()
    engine = create_engine(resolved)
    session_factory = create_session_factory(engine)
    context = ActivityContext(session_factory=session_factory)

    temporal_client = client or await connect(resolved)
    worker = Worker(
        temporal_client,
        task_queue=task_queue or resolved.temporal_task_queue or TASK_QUEUE,
        workflows=list(WORKFLOWS),
        activities=[
            context.create_run,
            context.record_transition,
            context.collect_context,
            context.plan_actions,
        ],
    )
    return WorkerHandle(worker=worker, client=temporal_client, _closers=[engine.dispose])


async def run_worker(settings: Settings | None = None) -> None:
    """Run until interrupted, then shut down cleanly."""
    resolved = settings or load_settings()
    configure_logging(level=resolved.log_level)

    handle = await build_worker(resolved)
    stopping = asyncio.Event()

    def _request_stop(_signum: int, _frame: FrameType | None) -> None:
        stopping.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(ValueError, AttributeError, OSError):
            # Signal handlers are unavailable off the main thread and SIGTERM does not
            # exist on Windows. Neither is fatal; the worker still stops on cancellation.
            signal.signal(sig, _request_stop)

    log.info(
        "worker starting",
        task_queue=handle.worker.config()["task_queue"],
        workflows=[w.__name__ for w in WORKFLOWS],
    )
    try:
        async with handle.worker:
            await stopping.wait()
        log.info("worker stopped cleanly")
    finally:
        await handle.aclose()


def main() -> int:
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
