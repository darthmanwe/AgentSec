"""``agentsec approve | deny | list`` (AS-021).

**Operator authentication happens here, at the ingress, and nowhere else.** Not in
workflow code, which may not perform I/O (AS-020), and not in the Temporal update handler,
whose validator must stay pure. By the time a decision reaches the database it has already
been attributed to an authenticated operator; by the time it reaches the workflow it is
just a notification that something changed.

That ordering is what makes the Temporal notification safe to expose. It carries no
authority: the workflow re-reads the decision from the database on every wake, so the
worst an attacker with namespace access can do is cause a redundant read.

Authentication is a shared token compared in constant time, and the threat model says so
plainly — the point of this project is authorization, not building an identity provider.
The *expected* token is the deployment's ``AGENTSEC_OPERATOR_TOKEN``; the *presented* one
comes from the operator's own ``--token`` or ``AGENTSEC_APPROVAL_TOKEN``. On a single
developer machine those hold the same string, which is why this is demo-grade; they are
separate inputs so that a real deployment can separate them without a code change.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentsec.authz.approvals import (
    ApprovalError,
    ApprovalService,
    as_aware,
    authenticate_operator,
)
from agentsec.authz.models import Principal
from agentsec.config import Settings, load_settings
from agentsec.db.models import Approval, ApprovalState, Run

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENIED_AUTH = 3
"""Distinct from a generic error so a script can tell "bad token" from "no such approval"
without parsing the message."""


@dataclass(frozen=True, slots=True)
class Outcome:
    """What a command produced. Returned rather than printed so the whole flow is
    testable without capturing stdout."""

    code: int
    lines: tuple[str, ...] = ()


# --------------------------------------------------------------------------- helpers


def _presented_token(args: argparse.Namespace) -> str | None:
    """The operator's own credential.

    A distinct variable from the deployment's expected token. Reading both from the same
    place would make the comparison theatre.
    """
    return args.token or os.environ.get("AGENTSEC_APPROVAL_TOKEN")


def _authenticate(args: argparse.Namespace, settings: Settings) -> Principal | None:
    expected = (
        settings.operator_token.get_secret_value() if settings.operator_token is not None else None
    )
    return authenticate_operator(
        _presented_token(args),
        expected,
        operator_id=args.operator_id or os.environ.get("USERNAME") or "operator",
    )


def _sessions(settings: Settings) -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(settings.database_url.get_secret_value())
    return async_sessionmaker(engine, expire_on_commit=False)


def _remaining(approval: Approval, now: dt.datetime) -> str:
    seconds = int((as_aware(approval.expires_at) - now).total_seconds())
    if seconds <= 0:
        return "lapsed"
    if seconds < 90:  # a display threshold, not a policy constant
        return f"{seconds}s"
    return f"{seconds // 60}m"


# --------------------------------------------------------------------------- commands


async def _decide(args: argparse.Namespace, settings: Settings, *, approved: bool) -> Outcome:
    operator = _authenticate(args, settings)
    if operator is None:
        # Fail closed and say which of the two inputs is missing, because "unauthorized"
        # with an unset expected token is a configuration problem, not an access problem.
        hint = (
            "AGENTSEC_OPERATOR_TOKEN is not configured for this deployment"
            if settings.operator_token is None
            else "presented token did not match; set --token or AGENTSEC_APPROVAL_TOKEN"
        )
        return Outcome(EXIT_DENIED_AUTH, (f"not authenticated as an operator: {hint}",))

    factory = _sessions(settings)
    async with factory() as session:
        service = ApprovalService(session)
        try:
            approval = await service.decide(
                args.approval_id, approver=operator, approved=approved, note=args.note
            )
        except ApprovalError as error:
            # Commit, not roll back. The reflexive rollback here is wrong and the test
            # suite found it: deciding a lapsed approval marks it EXPIRED and *then*
            # raises, so discarding the transaction leaves the row PENDING forever - an
            # approval that can never be decided sitting in the queue looking like work
            # somebody still owes. Every other branch raises before writing anything, so
            # committing is a no-op there rather than a risk.
            await session.commit()
            return Outcome(EXIT_ERROR, (str(error),))

        run = await session.get(Run, approval.run_id)
        workflow_id = run.workflow_id if run else None
        digest = approval.action_digest
        state = approval.state.value
        await session.commit()

    lines = [f"{args.approval_id}: {state} by {operator.id}"]

    # The decision is already durable. Waking the workflow is an optimisation - if it
    # fails, the run's own poll picks the decision up within its poll interval. Reporting
    # the failure matters; treating it as a failed approval would be wrong.
    if workflow_id and not args.no_notify:
        notified = await _notify(settings, workflow_id, args.approval_id, digest)
        lines.append(notified)

    return Outcome(EXIT_OK, tuple(lines))


async def _notify(settings: Settings, workflow_id: str, approval_id: str, digest: str) -> str:
    """Best-effort wake-up. Carries no authority; see the module docstring."""
    from temporalio.client import Client

    from agentsec.workflows.shared import ApprovalNudge

    try:
        client = await Client.connect(settings.temporal_address, namespace="agentsec")
        handle = client.get_workflow_handle(workflow_id)
        await handle.execute_update(
            "approval_decided", ApprovalNudge(approval_id=approval_id, action_digest=digest)
        )
    except Exception as error:  # any transport failure here is non-fatal, by design
        return f"  workflow not notified ({type(error).__name__}); it will poll: {workflow_id}"
    return f"  workflow notified: {workflow_id}"


async def _list(args: argparse.Namespace, settings: Settings) -> Outcome:
    """List approvals. Deliberately readable without a token.

    Seeing that a decision is outstanding is not the same authority as making it, and
    requiring a credential to look is how a queue ends up unattended.
    """
    now = dt.datetime.now(dt.UTC)
    factory = _sessions(settings)
    async with factory() as session:
        statement = select(Approval).order_by(Approval.created_at.desc()).limit(args.limit)
        if args.run:
            statement = statement.where(Approval.run_id == args.run)
        if not args.all:
            statement = statement.where(Approval.state == ApprovalState.PENDING)
        approvals = list((await session.execute(statement)).scalars())

    if not approvals:
        return Outcome(EXIT_OK, ("no approvals match",))

    lines = [f"{'APPROVAL':<24} {'RUN':<20} {'STATE':<10} {'EXPIRES':<8} DIGEST"]
    lines += [
        f"{a.id:<24} {a.run_id:<20} {a.state.value:<10} "
        f"{_remaining(a, now):<8} {a.action_digest[:16]}"
        for a in approvals
    ]
    return Outcome(EXIT_OK, tuple(lines))


# --------------------------------------------------------------------------- wiring


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsec", description="Operate the AgentSec human-in-the-loop approval gate."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    def add_auth(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("approval_id", help="the approval to decide")
        sub.add_argument("--note", help="recorded alongside the decision")
        sub.add_argument("--token", help="operator token; defaults to AGENTSEC_APPROVAL_TOKEN")
        sub.add_argument("--operator-id", help="who is deciding; recorded on the approval")
        sub.add_argument(
            "--no-notify",
            action="store_true",
            help="skip the Temporal wake-up; the run picks the decision up when it polls",
        )

    add_auth(subcommands.add_parser("approve", help="approve one exact action"))
    add_auth(subcommands.add_parser("deny", help="refuse one exact action"))

    listing = subcommands.add_parser("list", help="show approvals")
    listing.add_argument("--run", help="only this run")
    listing.add_argument("--all", action="store_true", help="include decided approvals")
    listing.add_argument("--limit", type=int, default=50)

    return parser


async def run(argv: Sequence[str] | None = None, settings: Settings | None = None) -> Outcome:
    """The whole command, minus process concerns. Tests call this directly."""
    args = build_parser().parse_args(argv)
    resolved = settings if settings is not None else load_settings()

    if args.command == "approve":
        return await _decide(args, resolved, approved=True)
    if args.command == "deny":
        return await _decide(args, resolved, approved=False)
    return await _list(args, resolved)


def main(argv: Sequence[str] | None = None) -> int:
    outcome = asyncio.run(run(argv))
    for line in outcome.lines:
        print(line)  # this is a terminal program; stdout is its output
    return outcome.code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["EXIT_DENIED_AUTH", "EXIT_ERROR", "EXIT_OK", "Outcome", "build_parser", "main", "run"]
