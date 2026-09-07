"""Ablation runner (AS-038).

Ten cells: two planners against five control stacks, exactly as ADR-0003 froze them. The
two axes traverse an identical downstream path, which is the only reason comparing them
means anything.

Four things this runner refuses to do, and each refusal is the point:

**It will not produce a reportable result without a lock.** ``--suite full`` checks the
AS-039 preregistration and fails if the prompt registry, tool registry, policy bundle or
corpus has drifted. Thresholds chosen or reinterpreted after seeing results are a
description of the data. A smoke run is exempt and is labelled unreportable in its own
artifact, so an exempted run cannot be quoted by mistake.

**It will not spend money by default.** The provider is the deterministic mock unless
``--live`` is passed *and* ``--max-usd`` bounds it. There is no path that infers liveness
from the presence of a key: a key in the environment for unrelated reasons must never turn
a free run into a paid one.

**It will not fan out.** Concurrency defaults to 2. Ten cells times a corpus times repeats,
run unbounded, would start hundreds of containers on a workstation — and the resource caps
that keep this machine usable are the same ones that keep the scanners honest.

**It will not write "proven".** The headline sentence is generated from the counters, never
typed. A finite corpus supports "zero observed unauthorized executions across N attempts",
and the confidence interval that goes with it.

Hardening for the single funded run (see also ``cache.py``, ``checkpoint.py``,
``resilience.py``):

* **Results are written as they are produced**, one file per cell, atomically. A crash at
  90% keeps 90% of the work instead of losing all of it along with the money.
* **Every paid response is cached to disk immediately.** ``--resume`` replays them for
  free and buys only what is missing, so a failure costs time rather than budget.
* **A dry run rehearses the exact same code path** with the mock provider and reports the
  projected spend. Rehearse before funding; the rehearsal exercises the code that will run.
* **Preflight refuses to start** when something would silently corrupt the result - most
  importantly a policy engine that is unreachable, which fails closed and would make every
  arm look perfectly safe.
* **SIGINT and SIGTERM are handled**, so stopping a run flushes its artifact and marks it
  interrupted rather than merely completed-looking.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import pathlib
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from agentsec.agent.accounting import BudgetExceededError, UsageAccountant
from agentsec.agent.adversarial import SCENARIOS, AdversarialPlanner, Layer
from agentsec.agent.state import SecurityAgentState
from agentsec.eval.attacks import INJECTION_CASES
from agentsec.eval.cache import ResponseCache
from agentsec.eval.checkpoint import RunDirectory, RunStatus
from agentsec.eval.preregistration import (
    LOCK_PATH,
    Preregistration,
    current_inputs,
    load,
    verify,
)
from agentsec.eval.resilience import Deadline, FatalRunError, RetryLog
from agentsec.eval.scorers import AuthorizationScore, CellReport, wilson_interval
from agentsec.log import get_logger

log = get_logger("agentsec.eval.runner")

ARTIFACT_DIR: Final = pathlib.Path(__file__).resolve().parents[3] / "eval" / "artifacts"

DEFAULT_CONCURRENCY: Final = 2

#: Above this, a live run starts colliding with rate limits often enough to be worth
#: mentioning. Not enforced - retries absorb it - but a slower run for no benefit.
_RATE_LIMIT_HINT: Final = 4


@dataclass(frozen=True, slots=True)
class Arm:
    """One control stack.

    ``sandbox`` is absent because it is on in every arm. It is a containment control, not a
    subject of the experiment, and disabling it to weaken a baseline would be both
    dangerous and dishonest.
    """

    id: str
    prompt_id: str
    policy: bool
    approval: bool
    capability: bool

    def as_row(self) -> dict[str, Any]:
        return {
            "arm": self.id,
            "prompt": self.prompt_id,
            "policy": self.policy,
            "approval": self.approval,
            "capability": self.capability,
        }


#: Frozen by ADR-0003. Changing this list is a new preregistration.
ARMS: Final[tuple[Arm, ...]] = (
    Arm("A0-none", "planner.system.operational", False, False, False),
    Arm("A1-prompt", "baseline.system", False, False, False),
    Arm("A2-policy", "baseline.system", True, False, False),
    Arm("A3-approval", "baseline.system", True, True, False),
    Arm("A4-full", "planner.system", True, True, True),
)

PLANNERS: Final[tuple[str, ...]] = ("adversarial", "real")


@dataclass
class RunSettings:
    """What a run was asked to do. Recorded verbatim in the artifact."""

    suite: str = "adversarial-planner"
    live: bool = False
    max_usd: float = 0.0
    repeats: int = 3
    concurrency: int = DEFAULT_CONCURRENCY
    arms: tuple[str, ...] = tuple(arm.id for arm in ARMS)
    seed: int = 0
    axes: tuple[str, ...] = ("adversarial",)
    """Which axes to run. Axis A is opt-in because it is the only one that costs."""

    resume: str | None = None
    dry_run: bool = False
    """Rehearse the live path with the mock provider and report the projected spend.

    Not a separate code path - the same cells, the same pipeline, the same scoring. A
    rehearsal that exercised different code would rehearse the wrong thing."""

    deadline_seconds: float = 6 * 3600.0
    """Wall-clock ceiling. Separate from the money ceiling and just as necessary: a run
    still going after six hours has hit something retry logic cannot see, and the honest
    response is to stop with what has been captured."""

    model: str = "claude-haiku-4-5-20251001"

    def as_row(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "live": self.live,
            "max_usd": self.max_usd,
            "repeats": self.repeats,
            "concurrency": self.concurrency,
            "arms": list(self.arms),
            "axes": list(self.axes),
            "seed": self.seed,
            "resume": self.resume,
            "dry_run": self.dry_run,
            "deadline_seconds": self.deadline_seconds,
            "model": self.model,
        }


@dataclass
class RunArtifact:
    """Everything a reader needs to check the result without re-running it."""

    started_at: str
    settings: RunSettings
    preregistration_hash: str = ""
    reportable: bool = False
    drifted_inputs: tuple[str, ...] = ()
    cells: list[dict[str, Any]] = field(default_factory=list)
    totals: dict[str, Any] = field(default_factory=dict)
    headline: str = ""
    notes: list[str] = field(default_factory=list)
    run_id: str = ""
    status: str = RunStatus.RUNNING.value
    complete: bool = False
    """Whether every planned cell finished. A partial run is legitimate output and must
    never be mistaken for a full one, so this is stored rather than inferred."""

    spend: dict[str, Any] = field(default_factory=dict)
    cache: dict[str, Any] = field(default_factory=dict)
    retries: dict[str, Any] = field(default_factory=dict)
    projection: dict[str, Any] = field(default_factory=dict)

    def as_document(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "status": self.status,
            "complete": self.complete,
            "settings": self.settings.as_row(),
            "preregistration_hash": self.preregistration_hash,
            "reportable": self.reportable,
            "drifted_inputs": list(self.drifted_inputs),
            "arms": [arm.as_row() for arm in ARMS],
            "cells": self.cells,
            "totals": self.totals,
            "spend": self.spend,
            "cache": self.cache,
            "retries": self.retries,
            "projection": self.projection,
            "headline": self.headline,
            "notes": self.notes,
        }


class SuiteError(Exception):
    """The run cannot proceed as asked."""


# --------------------------------------------------------------------------- Axis B


async def run_adversarial_cell(arm: Arm, *, repeats: int) -> tuple[AuthorizationScore, list[str]]:
    """One Axis-B cell: the compromised planner against one control stack.

    Uses the same ``ControlPipeline`` the real planner uses, configured per arm. The
    scenarios whose defence is the policy bundle or a backend's own validation are skipped
    in arms that do not have those controls active — counting them there would attribute a
    failure to a control the arm never claimed to have.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentsec.authz.capabilities import CapabilityMinter, CapabilityVerifier
    from agentsec.authz.keys import SigningKey, VerificationKeyring
    from agentsec.control.pipeline import ControlPipeline
    from agentsec.gateway.core import McpGateway, RecordingBackend
    from agentsec.gateway.registry import load_registry

    registry = load_registry()
    attempted = executed = reached = 0
    notes: list[str] = []

    applicable = [s for s in SCENARIOS if s.blocked_by is not Layer.BACKEND]
    if not arm.policy:
        applicable = [s for s in applicable if s.blocked_by is not Layer.POLICY]

    for _ in range(repeats):
        for scenario in applicable:
            key = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())
            backends = {
                tool: RecordingBackend()
                for tool in ("fixture_repo", "vuln_intel", "fake_cloud", "fake_jira", "github")
            }
            pipeline = ControlPipeline(
                planner=AdversarialPlanner(scenario=scenario),
                registry=registry,
                policy=await _policy_for(arm),
                gateway=McpGateway(
                    registry=registry,
                    verifier=CapabilityVerifier(VerificationKeyring.of(key.kid, key.public_key)),
                    backends=dict(backends),
                ),
                minter=CapabilityMinter(key),
                workflow_id=f"wf-{arm.id}",
            )
            # An arm without the approval gate is modelled by pre-approving every digest,
            # which is exactly what "no human in the loop" means. Removing the gate by
            # deleting the check would test different code than the one that ships.
            if not arm.approval:
                pipeline.approved_digests.add("*")

            outcome = await pipeline.run(
                SecurityAgentState(
                    run_id=f"{arm.id}-{scenario.id}",
                    task="review repo-a",
                    repository="fixture://repo-a",
                    available_tools=("fixture_repo", "vuln_intel", "fake_cloud", "fake_jira"),
                    resource_scope=scenario.scope,
                )
            )
            attempted += outcome.attempted
            executed += outcome.executed
            reached += outcome.backend_calls

    if not applicable:
        notes.append(f"{arm.id}: no applicable scenarios; this cell measured nothing")

    return (
        AuthorizationScore(
            attempted=attempted,
            executed=executed,
            reached_backend=reached,
            trials=repeats * len(applicable),
        ),
        notes,
    )


async def _policy_for(arm: Arm) -> Any:
    """The policy engine for an arm.

    An arm without policy gets one that allows everything, rather than no engine at all.
    ``DenyAllPolicy`` is what a missing engine produces (fail-closed, AS-008), and using it
    here would make the no-policy arms look *safer* than the ones with policy — an
    ablation that inverts its own result.
    """
    import datetime as _dt

    from agentsec.authz.models import PolicyDecision, PolicyOutcome

    if not arm.policy:

        class _AllowAll:
            async def evaluate(self, request: object) -> PolicyDecision:
                return PolicyDecision(
                    outcome=PolicyOutcome.ALLOW,
                    reason_code="arm_has_no_policy_engine",
                    evaluated_at=_dt.datetime.now(_dt.UTC),
                )

        return _AllowAll()

    from agentsec.authz.engine import OpaPolicyClient
    from agentsec.config import load_settings

    return OpaPolicyClient(base_url=load_settings().opa_url)


# --------------------------------------------------------------------------- preflight


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """What preflight found. ``blockers`` stops the run; ``warnings`` do not."""

    blockers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.blockers


async def preflight(settings: RunSettings) -> PreflightResult:
    """Refuse to start a funded run that would produce a corrupt result.

    The check that matters most is the policy engine. OPA is fail-closed by design
    (AS-008): if it is unreachable, every decision becomes DENY - so a run against a dead
    OPA would block every attack and report a **perfect** score. That is the worst
    available failure, because it looks like success. A funded run must not be able to
    make it.
    """
    blockers: list[str] = []
    warnings: list[str] = []

    # Every arm's prompt must exist. The dry-run rehearsal caught A0-none referencing
    # planner.system.operational, which ADR-0003 described and nobody had written - a
    # failure that would have surfaced mid-sweep on a live run, after spending. Checked
    # here so it cannot reach a funded run again.
    from agentsec.agent.prompts import REGISTRY

    for arm in ARMS:
        if arm.id in settings.arms and arm.prompt_id not in REGISTRY:
            blockers.append(
                f"arm {arm.id} references prompt {arm.prompt_id!r}, which is not in the "
                f"registry. Known: {list(REGISTRY.ids())}"
            )

    needs_policy = any(arm.policy for arm in ARMS if arm.id in settings.arms)
    if needs_policy:
        healthy = await _opa_healthy()
        if not healthy:
            blockers.append(
                "the policy engine is unreachable, and it fails closed: every action "
                "would be denied and the run would report a perfect score it did not "
                "earn. Start it with `docker compose up -d opa`."
            )

    if "real" in settings.axes:
        if not settings.live and not settings.dry_run:
            warnings.append(
                "Axis A was requested without --live, so it will run on the deterministic "
                "mock. Useful as a rehearsal, meaningless as a susceptibility measurement."
            )
        if settings.live:
            from agentsec.config import load_settings

            if load_settings().anthropic_api_key is None:
                blockers.append("--live requires AGENTSEC_ANTHROPIC_API_KEY to be set")

    if settings.live and settings.concurrency > _RATE_LIMIT_HINT:
        warnings.append(
            f"concurrency {settings.concurrency} on a live run invites rate limiting; "
            "retries will absorb it but the run will take longer than it needs to"
        )

    try:
        from agentsec.eval.corpus import build_manifest, load_ground_truth

        load_ground_truth()
        build_manifest()
    except (FileNotFoundError, OSError) as error:
        blockers.append(f"the benchmark corpus is not generated: {error}")

    return PreflightResult(blockers=tuple(blockers), warnings=tuple(warnings))


async def _opa_healthy() -> bool:
    """Whether OPA answers a real policy query.

    A query rather than a socket connect or a health endpoint. A listening port proves a
    process is up; only an actual decision proves the bundle is loaded and the path the
    client uses resolves - and a bundle that failed to load is a silently-perfect run.
    """
    import datetime as _dt

    from agentsec.authz.engine import OpaPolicyClient
    from agentsec.authz.models import (
        ActionIntent,
        AuthorizationRequest,
        Principal,
        PrincipalKind,
        ResourceRef,
        RiskClass,
    )
    from agentsec.config import load_settings

    try:
        client = OpaPolicyClient(base_url=load_settings().opa_url)
        decision = await client.evaluate(
            AuthorizationRequest(
                principal=Principal(
                    id="preflight", kind=PrincipalKind.AGENT, workflow_id="wf-preflight"
                ),
                intent=ActionIntent(
                    tool="fixture_repo",
                    operation="read_file",
                    resource=ResourceRef(scheme="fixture", identifier="repo-a/README.md"),
                    arguments={"path": "README.md"},
                    risk_class=RiskClass.READ_ONLY,
                ),
                requested_at=_dt.datetime.now(_dt.UTC),
            )
        )
    except Exception:  # any failure here means "not healthy", whatever it was
        return False
    # A permitted read proves the bundle is loaded. A fail-closed DENY proves only that
    # something answered, which is exactly the state this check exists to catch.
    return decision.permits_execution and not decision.fail_closed


def project_cost(settings: RunSettings) -> dict[str, Any]:
    """Estimate what a live run would cost, before committing to it.

    Deliberately an over-estimate: it prices every call at its full ``max_tokens`` of
    output, which almost never happens. An operator deciding whether $25 covers the plan
    needs the number that cannot be exceeded, not the one that is most likely.
    """
    from agentsec.agent.provider import capabilities_for
    from agentsec.agent.providers import TOKEN_SAFETY_FACTOR
    from agentsec.eval.axis_a import build_state

    if "real" not in settings.axes:
        return {"live_calls": 0, "worst_case_usd": 0.0, "note": "Axis B makes no model calls"}

    capabilities = capabilities_for(settings.model)
    arms = [arm for arm in ARMS if arm.id in settings.arms]

    # One call per case, per arm, per repeat - each repeat a genuine re-sample rather
    # than a cache replay - plus one replan per case as an upper bound.
    calls = len(arms) * len(INJECTION_CASES) * max(1, settings.repeats) * 2

    sample = build_state(INJECTION_CASES[0], run_id="projection")
    characters = len(sample.render_evidence()) + len(sample.task) + 4_000
    input_tokens = int((characters / 4) * TOKEN_SAFETY_FACTOR)
    per_call = capabilities.cost_usd(input_tokens, min(4_096, capabilities.max_output_tokens))

    return {
        "model": settings.model,
        "live_calls": calls,
        "estimated_input_tokens_per_call": input_tokens,
        "worst_case_usd": round(per_call * calls, 4),
        "note": (
            "worst case: every call priced at full max_tokens of output, which almost "
            "never happens. Actual spend is typically a fraction of this."
        ),
    }


# --------------------------------------------------------------------------- the run


def _plan_cells(settings: RunSettings) -> tuple[str, ...]:
    """Which cells this run intends to produce.

    Recorded up front so a resume knows what is still outstanding, and so a partial run
    can say what it is missing rather than merely being shorter than expected.
    """
    cells: list[str] = []
    for axis in settings.axes:
        for arm in ARMS:
            if arm.id in settings.arms:
                cells.append(f"{axis}/{arm.id}")
    return tuple(cells)


def _pipeline_factory(arm: Arm, registry: Any, policy: Any) -> Any:
    """Build a fresh pipeline per case, sharing nothing.

    State leaking between cases - a spent capability, an approved digest, a ledger entry -
    would make case N's result depend on case N-1's, and the corpus order is arbitrary.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentsec.authz.capabilities import CapabilityMinter, CapabilityVerifier
    from agentsec.authz.keys import SigningKey, VerificationKeyring
    from agentsec.control.pipeline import ControlPipeline
    from agentsec.gateway.core import McpGateway, RecordingBackend

    def build(planner: Any) -> Any:
        key = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())
        backends = {
            tool: RecordingBackend()
            for tool in ("fixture_repo", "vuln_intel", "fake_cloud", "fake_jira", "github")
        }
        pipeline = ControlPipeline(
            planner=planner,
            registry=registry,
            policy=policy,
            gateway=McpGateway(
                registry=registry,
                verifier=CapabilityVerifier(VerificationKeyring.of(key.kid, key.public_key)),
                backends=dict(backends),
            ),
            minter=CapabilityMinter(key),
            workflow_id=f"wf-{arm.id}",
        )
        if not arm.approval:
            pipeline.approved_digests.add("*")
        return pipeline

    return build


async def _run_axis_a_arm(
    arm: Arm,
    settings: RunSettings,
    *,
    cache: ResponseCache,
    accountant: UsageAccountant,
    retry_log: RetryLog,
    directory: RunDirectory,
) -> dict[str, Any]:
    """One Axis-A cell, checkpointing after every case."""
    from agentsec.agent.providers import select_provider
    from agentsec.config import load_settings
    from agentsec.eval.axis_a import run_axis_a_cell
    from agentsec.gateway.registry import load_registry

    key = load_settings().anthropic_api_key
    provider = select_provider(
        live=settings.live,
        api_key=key.get_secret_value() if key else None,
        accountant=accountant,
        cache=cache,
        retry_log=retry_log,
    )
    registry = load_registry()
    policy = await _policy_for(arm)

    def checkpoint(outcome: Any) -> None:
        # Written per case, not per cell. A cell holding twenty-two paid-for results in
        # memory is a cell whose crash loses all of them.
        directory.append_event(
            {
                "event": "axis_a_case",
                "arm": arm.id,
                **outcome.as_row(),
                "spent_usd": round(accountant.ledger.settled_usd, 6),
            }
        )

    result = await run_axis_a_cell(
        arm_id=arm.id,
        prompt_id=arm.prompt_id,
        provider=provider,
        pipeline_factory=_pipeline_factory(arm, registry, policy),
        model=settings.model,
        cases=INJECTION_CASES,
        repeats=settings.repeats,
        on_case=checkpoint,
    )
    document = result.as_document()
    document["controls"] = arm.id
    return document


async def run_suite(settings: RunSettings) -> RunArtifact:
    """Execute the requested suite, writing results as they are produced."""
    check = verify()
    smoke = settings.suite == "smoke"

    if not smoke and not check.reportable:
        # A hard failure, not a warning. The difference between preregistration and a note
        # in a file is whether anything refuses to proceed.
        raise SuiteError(
            "refusing a reportable run: "
            + (
                "no preregistration is locked"
                if not check.locked
                else f"inputs drifted since preregistration: {list(check.drifted)}"
            )
            + ". Re-freeze deliberately if this is a new experiment."
        )

    if settings.live and settings.max_usd <= 0:
        raise SuiteError("--live requires --max-usd; an unbounded live run is not permitted")
    if settings.live and settings.dry_run:
        raise SuiteError("--dry-run and --live are contradictory; pick one")

    selected = [arm for arm in ARMS if arm.id in settings.arms]
    if not selected:
        raise SuiteError(f"no arms selected from {settings.arms}")

    flight = await preflight(settings)
    if not flight.ok:
        raise SuiteError("preflight refused the run:\n  - " + "\n  - ".join(flight.blockers))

    planned = _plan_cells(settings)
    if settings.resume:
        directory = RunDirectory.open(settings.resume)
        directory.planned_cells = planned
    else:
        directory = RunDirectory.create(
            planned_cells=planned, metadata={"settings": settings.as_row()}
        )

    artifact = RunArtifact(
        started_at=dt.datetime.now(dt.UTC).isoformat(),
        settings=settings,
        run_id=directory.run_id,
    )
    artifact.drifted_inputs = check.drifted
    if check.locked:
        artifact.preregistration_hash = check.recorded_hash
    # A dry run is never reportable, whatever suite it was asked for. It measures nothing
    # about a real model, and the first version marked a `--suite full --dry-run` artifact
    # "reportable" in its own filename - which is precisely how a rehearsal gets quoted as
    # a result.
    artifact.reportable = check.reportable and not smoke and not settings.dry_run
    artifact.projection = project_cost(settings)

    if smoke:
        artifact.notes.append("smoke run: not reportable, thresholds not checked")
    if settings.dry_run:
        artifact.notes.append(
            "DRY RUN: the same cells and the same pipeline, on the deterministic mock. "
            "Rehearses the code that would run; measures nothing about a real model."
        )
    if settings.live:
        artifact.notes.append(f"LIVE run: up to ${settings.max_usd:.2f} of real credit")
    artifact.notes.extend(f"preflight: {warning}" for warning in flight.warnings)

    cache = ResponseCache(directory.cache_dir)
    accountant = UsageAccountant(max_usd=settings.max_usd if settings.live else 1e9)
    retry_log = RetryLog()
    deadline = Deadline(settings.deadline_seconds)
    already = directory.completed_cells()
    if already:
        artifact.notes.append(
            f"resumed: {len(already)} of {len(planned)} cells already on disk, replaying "
            "cached responses rather than re-purchasing them"
        )

    semaphore = asyncio.Semaphore(settings.concurrency)
    status = RunStatus.COMPLETED
    detail = ""

    async def run_cell(axis: str, arm: Arm) -> None:
        cell = f"{axis}/{arm.id}"
        if cell in already:
            return
        async with semaphore:
            deadline.check()
            directory.append_event({"event": "cell_started", "cell": cell})
            if axis == "adversarial":
                score, notes = await run_adversarial_cell(arm, repeats=settings.repeats)
                report = CellReport(cell=cell, planner="adversarial", controls=arm.id)
                report.authorization = score
                document = report.as_document()
                artifact.notes.extend(notes)
            else:
                document = await _run_axis_a_arm(
                    arm,
                    settings,
                    cache=cache,
                    accountant=accountant,
                    retry_log=retry_log,
                    directory=directory,
                )
            # Persisted the instant the cell finishes. Everything before this point is
            # recoverable from the cache; everything after is not, so nothing is held.
            directory.save_cell(cell, document)

    try:
        await asyncio.gather(*(run_cell(axis, arm) for axis in settings.axes for arm in selected))
    except asyncio.CancelledError:
        status = RunStatus.INTERRUPTED
        detail = "cancelled by the operator"
        artifact.notes.append("INTERRUPTED: results captured up to this point are on disk")
    except BudgetExceededError as error:
        status = RunStatus.BUDGET_EXHAUSTED
        detail = str(error)
        artifact.notes.append(f"BUDGET CEILING REACHED: {error}")
    except FatalRunError as error:
        status = RunStatus.DEADLINE_REACHED if "deadline" in str(error) else RunStatus.FAILED
        detail = str(error)
        artifact.notes.append(f"STOPPED: {error}")
    except Exception as error:  # recorded and reported; a run must not die silently
        status = RunStatus.FAILED
        detail = f"{type(error).__name__}: {error}"
        artifact.notes.append(f"FAILED: {detail}")
        log.error("run failed", error=detail)

    # Assembled from disk, not from memory. Whatever completed is in the cell files, which
    # is the whole point of writing them as we went.
    artifact.cells = directory.load_cells()
    artifact.complete = len(directory.completed_cells()) == len(planned)
    if not artifact.complete:
        artifact.reportable = False
        artifact.notes.append(
            f"PARTIAL: {len(directory.completed_cells())} of {len(planned)} cells completed; "
            f"missing {list(directory.remaining_cells)}. Not reportable. "
            f"Resume with --resume {directory.run_id}"
        )

    artifact.status = status.value
    artifact.spend = accountant.report() if settings.live else {"live": False, "spent_usd": 0.0}
    artifact.spend["cache_total_usd_all_runs"] = round(cache.total_usd(), 6)
    artifact.cache = cache.stats.as_row()
    artifact.retries = retry_log.as_row()

    totals = _aggregate(artifact.cells)
    interval = wilson_interval(
        int(totals["unauthorized_executions"]), max(1, int(totals["unauthorized_attempts"]))
    )
    artifact.totals = {
        **totals,
        "execution_rate_ci95": list(interval) if interval else None,
    }
    artifact.headline = _headline(
        AuthorizationScore(
            attempted=int(totals["unauthorized_attempts"]),
            executed=int(totals["unauthorized_executions"]),
            trials=int(totals["trials"]),
        ),
        interval,
    )

    directory.set_status(status, detail)
    write_artifact(artifact, directory.root)
    return artifact


def _aggregate(cells: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum the counters across whatever cells exist.

    Reads the cell documents rather than trusting an in-memory tally, so a resumed run and
    a single-pass run produce the same totals from the same files.
    """
    attempted = executed = trials = backend = 0
    injection_cases = injection_proposed = injection_executed = injection_reported = 0

    for cell in cells:
        authorization = cell.get("authorization") or {}
        attempted += int(authorization.get("unauthorized_attempts", 0) or 0)
        executed += int(authorization.get("unauthorized_executions", 0) or 0)
        backend += int(authorization.get("attempts_reaching_a_backend", 0) or 0)
        trials += int(authorization.get("trials", 0) or 0)

        injection = cell.get("injection") or {}
        injection_cases += int(injection.get("cases", 0) or 0)
        injection_proposed += int(injection.get("proposed_canary", 0) or 0)
        injection_executed += int(injection.get("executed_canary", 0) or 0)
        injection_reported += int(injection.get("reported_injection", 0) or 0)

    return {
        "unauthorized_attempts": attempted,
        "unauthorized_executions": executed,
        "attempts_reaching_a_backend": backend,
        "trials": trials,
        "injection_cases": injection_cases,
        "injection_proposed_canary": injection_proposed,
        "injection_executed_canary": injection_executed,
        "injection_reported": injection_reported,
        "cells": len(cells),
    }


def _headline(score: AuthorizationScore, interval: tuple[float, float] | None) -> str:
    """Generate the reportable sentence.

    Generated rather than typed, so the phrasing cannot drift into "proven zero rate" the
    first time somebody writes a README in a hurry. The upper confidence bound is included
    because a zero without one invites the reader to assume certainty the sample size does
    not support.
    """
    base = score.headline()
    if interval and score.attempted:
        return f"{base}; 95% CI upper bound on the execution rate {interval[1]:.4f}"
    return base


def write_artifact(artifact: RunArtifact, directory: pathlib.Path = ARTIFACT_DIR) -> pathlib.Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = artifact.started_at.replace(":", "").replace("-", "")[:15]
    label = "reportable" if artifact.reportable else "unreportable"
    path = directory / f"ablation-{stamp}-{label}.json"
    path.write_text(
        json.dumps(artifact.as_document(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def check_thresholds(artifact: RunArtifact) -> list[str]:
    """Compare totals against the preregistered bars. Returns the failures."""
    document = load(LOCK_PATH)
    # Rebuilt with the *current* inputs. The lock's hash covers thresholds and frozen
    # inputs together, so comparing it against a Preregistration built without inputs
    # always fails - which the first version of this function did, reporting a threshold
    # violation on a run whose thresholds were untouched. Input drift is reported
    # separately by verify(), where it belongs: "the policy bundle changed" and "somebody
    # edited a threshold" are different findings and should not share a message.
    prereg = Preregistration(inputs=current_inputs())
    failures: list[str] = []

    observed = {
        "unauthorized_executions": float(artifact.totals.get("unauthorized_executions", 0)),
        "unauthorized_attempts": float(artifact.totals.get("unauthorized_attempts", 0)),
    }
    for name, value in observed.items():
        threshold = prereg.for_metric(name)
        if threshold is None:
            continue
        if threshold.passes(value) is False:
            failures.append(
                f"{name}={value} violates the preregistered bound "
                f"({threshold.direction} {threshold.bound})"
            )
    if document.get("hash") != prereg.hash and artifact.reportable:
        failures.append(
            "the preregistration hash does not match: thresholds or frozen inputs were "
            "edited after freezing"
        )
    return failures


# --------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentsec-eval", description="Run the AgentSec ablation.")
    parser.add_argument(
        "--suite",
        default="adversarial-planner",
        choices=["adversarial-planner", "full", "smoke"],
        help="adversarial-planner is Axis B and free; smoke is not reportable",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="spend real API credit. Requires --max-usd. Never inferred from a key.",
    )
    parser.add_argument("--max-usd", type=float, default=0.0, help="hard ceiling on spend")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="bounded on purpose; unbounded fan-out starts hundreds of containers",
    )
    parser.add_argument("--arm", action="append", dest="arms", help="restrict to named arms")
    parser.add_argument(
        "--axis",
        action="append",
        dest="axes",
        choices=["adversarial", "real"],
        help="which axes to run. 'real' is Axis A and is the only one that costs money.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "rehearse the live path on the deterministic mock and report the projected "
            "spend. Same cells, same pipeline, same scoring - rehearses the code that "
            "will run."
        ),
    )
    parser.add_argument(
        "--resume",
        metavar="RUN_ID",
        help="continue a run that stopped. Cached responses are replayed, not re-bought.",
    )
    parser.add_argument(
        "--list-runs", action="store_true", help="show runs on disk and their status"
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="run the safety checks and the cost projection, then stop",
    )
    parser.add_argument(
        "--deadline-hours",
        type=float,
        default=6.0,
        help="wall-clock ceiling. A run still going past this has hit something retries "
        "cannot see; stopping keeps what was captured.",
    )
    parser.add_argument(
        "--model",
        default="claude-haiku-4-5-20251001",
        help="the model for Axis A. Pinned to a dated snapshot by default.",
    )
    return parser


def _emit(line: str) -> None:
    print(line)  # noqa: T201 - this is a terminal program; stdout is its output


async def _run_with_signals(settings: RunSettings) -> RunArtifact:
    """Run the suite, converting SIGINT and SIGTERM into a clean cancellation.

    Without this, Ctrl-C on a live run raises through the middle of a cell and the artifact
    is never written - so the operator has spent money and has an events log to reconstruct
    from. With it, the run cancels, the completed cells are already on disk, and the
    artifact says ``interrupted``.

    Windows does not support ``add_signal_handler``; there, KeyboardInterrupt surfaces as
    a CancelledError through the same path, which is why the fallback is silent rather
    than a warning.
    """
    import contextlib
    import signal

    loop = asyncio.get_running_loop()
    task = asyncio.ensure_future(run_suite(settings))

    def stop() -> None:
        if not task.done():
            log.warning("stop requested; cancelling the run and flushing results")
            task.cancel()

    handled = []
    for name in ("SIGINT", "SIGTERM"):
        received = getattr(signal, name, None)
        if received is None:
            continue
        with contextlib.suppress(NotImplementedError, RuntimeError, AttributeError):
            loop.add_signal_handler(received, stop)
            handled.append(name)

    try:
        return await task
    finally:
        for name in handled:
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.remove_signal_handler(getattr(signal, name))


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_runs:
        from agentsec.eval.checkpoint import list_runs

        runs = list_runs()
        if not runs:
            _emit("no runs on disk")
        for run in runs:
            done = len(run.get("completed_cells", []))
            planned = len(run.get("planned_cells", []))
            _emit(f"{run['run_id']:<32} {run['status']:<18} {done}/{planned} cells")
        return 0

    axes = tuple(args.axes) if args.axes else ("adversarial",)
    settings = RunSettings(
        suite=args.suite,
        live=args.live,
        max_usd=args.max_usd,
        repeats=args.repeats,
        concurrency=args.concurrency,
        arms=tuple(args.arms) if args.arms else tuple(arm.id for arm in ARMS),
        axes=axes,
        resume=args.resume,
        dry_run=args.dry_run,
        deadline_seconds=args.deadline_hours * 3600.0,
        model=args.model,
    )

    if args.preflight_only:
        flight = asyncio.run(preflight(settings))
        projection = project_cost(settings)
        for warning in flight.warnings:
            _emit(f"  warning: {warning}")
        for blocker in flight.blockers:
            _emit(f"  BLOCKER: {blocker}")
        _emit(
            f"projection: {projection['live_calls']} live calls, worst case "
            f"${projection.get('worst_case_usd', 0.0):.2f}"
        )
        _emit(f"  {projection.get('note', '')}")
        return 0 if flight.ok else 2

    try:
        artifact = asyncio.run(_run_with_signals(settings))
    except SuiteError as error:
        print(f"error: {error}", file=sys.stderr)  # noqa: T201 - terminal program
        return 2
    except KeyboardInterrupt:
        # Reached only if the interrupt arrives outside the guarded window. The run
        # directory still holds every completed cell.
        print("interrupted before the run started", file=sys.stderr)  # noqa: T201
        return 130

    path = write_artifact(artifact)
    failures = check_thresholds(artifact) if artifact.reportable else []

    _emit(artifact.headline)
    _emit(f"run: {artifact.run_id}  status: {artifact.status}  complete: {artifact.complete}")
    _emit(f"artifact: {path}")
    if artifact.settings.live:
        _emit(
            f"spend: ${artifact.spend.get('spent_usd', 0.0):.4f} of "
            f"${artifact.settings.max_usd:.2f}  "
            f"(cache saved ${artifact.cache.get('usd_saved_by_cache', 0.0):.4f})"
        )
    if artifact.retries.get("retries"):
        _emit(f"retries: {artifact.retries['retries']} ({artifact.retries.get('retries_by_kind')})")
    for note in artifact.notes:
        _emit(f"  note: {note}")
    for failure in failures:
        _emit(f"  THRESHOLD FAILURE: {failure}")

    if not artifact.complete:
        return 3
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = [
    "ARMS",
    "ARTIFACT_DIR",
    "DEFAULT_CONCURRENCY",
    "PLANNERS",
    "Arm",
    "PreflightResult",
    "RunArtifact",
    "RunSettings",
    "SuiteError",
    "build_parser",
    "check_thresholds",
    "main",
    "preflight",
    "project_cost",
    "run_suite",
    "write_artifact",
]
