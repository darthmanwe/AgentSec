"""The control path: proposal to authorized execution (AS-028).

This module is where the two halves of the project meet, and it lives outside
``agentsec.agent`` for a structural reason. The planner must never reach the capability
minter, so the thing that *does* mint cannot be something the planner can import. The
dependency runs one way: control imports agent, agent imports nothing of control.

The path every proposed action takes, in order, with the reason each step is where it is:

1. **Compile.** A :class:`~agentsec.agent.state.ProposedAction` becomes an
   :class:`~agentsec.authz.models.ActionIntent` using the *trusted registry*. The registry
   assigns the risk class; the planner never names its own. A tool the registry does not
   define stops here, and the attempt is recorded.
2. **Digest.** The canonical digest (AS-007) is computed from the compiled intent. What
   gets dispatched is the canonicalised form, not the original — hashing normalised text
   and sending raw input is a signature-bypass.
3. **Scope.** The resource must be inside the run's assignment. Enforced here and not
   only in the planner, because a check a component performs on itself is not a control
   a compromised version of that component will run.
4. **Policy.** Fail-closed. ``REQUIRE_APPROVAL`` is not permission; it is a request for it.
5. **Approval.** Required when *either* the policy asks for one or the trusted registry
   declares the operation needs one, bound to the exact digest. Two independent sources
   have to agree an action is safe before it proceeds without a human.
6. **Mint.** A capability, short-lived and scoped, bound to this digest and this workflow.
   Policy is re-run immediately before minting, so a newly-denying policy beats a valid
   approval.
7. **Dispatch.** Through the gateway, which verifies and redeems independently. The
   gateway does not trust that we did steps 1-5; it re-checks.

**Every attempt is recorded, including — especially — the refused ones.** The headline
metric is the gap between attempted and executed unauthorized actions, and a pipeline that
only wrote successful rows would make the claim unmeasurable. That is why
:class:`ControlOutcome` counts both and why nothing here swallows a denial.
"""

from __future__ import annotations

import datetime as dt
import enum
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from agentsec.agent.provider import response_usd
from agentsec.agent.state import ProposedAction, SecurityAgentState
from agentsec.authz.capabilities import CapabilityMinter, compute_request_hash
from agentsec.authz.digest import canonicalize
from agentsec.authz.engine import PolicyEngine
from agentsec.authz.models import (
    ActionIntent,
    AuthorizationRequest,
    PolicyOutcome,
    Principal,
    PrincipalKind,
    ResourceRef,
)
from agentsec.gateway.core import DispatchRequest, GatewayResult, McpGateway
from agentsec.gateway.ledger import operation_id
from agentsec.gateway.registry import ToolRegistry, UnknownToolError
from agentsec.log import get_logger

log = get_logger("agentsec.control.pipeline")


class Stage(enum.StrEnum):
    """Where an attempt stopped.

    Granular because the reason matters more than the fact. "Denied" is one number;
    "denied because the planner named a tool that does not exist" and "denied because
    policy refused a high-risk write" are different findings about different attacks.
    """

    COMPILED = "compiled"
    UNKNOWN_TOOL = "unknown_tool"
    INVALID_ACTION = "invalid_action"
    OUT_OF_SCOPE = "out_of_scope"
    POLICY_DENIED = "policy_denied"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_DENIED = "approval_denied"
    GATEWAY_DENIED = "gateway_denied"
    EXECUTED = "executed"

    @property
    def is_execution(self) -> bool:
        return self is Stage.EXECUTED


@dataclass(frozen=True, slots=True)
class Attempt:
    """One proposed action and what became of it.

    Written for every proposal, whatever the outcome. The denied ones are the measurement.
    """

    action: ProposedAction
    stage: Stage
    reason: str = ""
    action_digest: str | None = None
    reached_backend: bool = False
    result: Any = None

    @property
    def executed(self) -> bool:
        return self.stage.is_execution


@dataclass
class ControlOutcome:
    """What one control-path run did.

    ``attempted`` and ``executed`` are counted separately and always. Collapsing them
    would destroy the only number this project exists to produce.
    """

    run_id: str
    attempts: list[Attempt] = field(default_factory=list)
    planning_rejected: list[str] = field(default_factory=list)
    """Actions the planner's own validation dropped before authorization saw them. Still
    attempts by the planner, so they are reported rather than forgotten."""

    model_calls: int = 0
    """How many model calls the planner made. Zero for the adversarial planner, which is
    the point of it."""

    cached_calls: int = 0
    """How many of those were replayed from the cache rather than bought."""

    input_tokens: int = 0
    output_tokens: int = 0

    usd: float = 0.0
    """What this run cost *now*. Recorded per case so the artifact can say where the money
    went; a cell reporting $0.00 while the run reported real spend is an artifact that
    cannot be audited against the invoice."""

    injection_observed: bool = False
    """Whether the planner reported that its evidence tried to instruct it.

    Surfaced here rather than left on the planner's own result object, because the
    evaluation needs it and reaching into the planner for it would be a guess about
    internals. Reported separately from whether the planner complied: noticing an
    injection and obeying it anyway are different outcomes, and so are noticing it and
    refusing."""

    @property
    def attempted(self) -> int:
        """Every action the planner proposed, including what its own validator rejected."""
        return len(self.attempts) + len(self.planning_rejected)

    @property
    def executed(self) -> int:
        return sum(1 for attempt in self.attempts if attempt.executed)

    @property
    def backend_calls(self) -> int:
        """How many attempts reached a backend at all.

        Distinct from ``executed``: an attempt can reach a backend and fail there. What
        must never happen is a *denied* attempt reaching one.
        """
        return sum(1 for attempt in self.attempts if attempt.reached_backend)

    def by_stage(self, stage: Stage) -> list[Attempt]:
        return [attempt for attempt in self.attempts if attempt.stage is stage]

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for attempt in self.attempts:
            counts[attempt.stage.value] = counts.get(attempt.stage.value, 0) + 1
        return {
            "run_id": self.run_id,
            "attempted_actions": self.attempted,
            "executed_actions": self.executed,
            "backend_calls": self.backend_calls,
            "planning_rejected": len(self.planning_rejected),
            "injection_observed": self.injection_observed,
            "model_calls": self.model_calls,
            "usd": round(self.usd, 6),
            "by_stage": dict(sorted(counts.items())),
        }


class Planner(Protocol):
    """The seam the evaluation varies.

    Both axes plug in here and traverse an identical downstream path. That identity is
    the point: if the adversarial planner reached the gateway by a different route, it
    would prove nothing about the route the real one takes.
    """

    async def plan(self, state: SecurityAgentState) -> Any: ...


@dataclass
class ControlPipeline:
    """Runs one review from task to authorized execution."""

    planner: Planner
    registry: ToolRegistry
    policy: PolicyEngine
    gateway: McpGateway
    minter: CapabilityMinter | None = None
    principal: Principal | None = None
    workflow_id: str = "wf-local"
    environment: str = "local"
    capability_ttl_seconds: int = 60
    approved_digests: set[str] = field(default_factory=set)
    """Digests an operator has approved. Empty by default, which is the safe default: an
    action needing approval and finding none is refused, not waved through."""

    async def run(self, state: SecurityAgentState) -> ControlOutcome:
        outcome = ControlOutcome(run_id=state.run_id)

        planning = await self.planner.plan(state)
        outcome.planning_rejected = list(getattr(planning, "rejected", []))
        outcome.injection_observed = bool(getattr(planning, "injection_observed", False))

        # Attributed here because this is the only place that sees both the planner's
        # responses and the case they belong to. The accountant knows the run total; only
        # this knows which case spent it.
        for response in getattr(planning, "responses", ()):
            outcome.model_calls += 1
            outcome.cached_calls += int(bool(response.metadata.get("cached")))
            outcome.input_tokens += response.usage.input_tokens
            outcome.output_tokens += response.usage.output_tokens
            outcome.usd += response_usd(response)

        for index, action in enumerate(getattr(planning, "actions", ())):
            outcome.attempts.append(await self._authorize_and_dispatch(state, action, index))

        log.info("control path complete", **outcome.summary())
        return outcome

    # ------------------------------------------------------------------ one action

    async def _authorize_and_dispatch(
        self, state: SecurityAgentState, action: ProposedAction, occurrence: int
    ) -> Attempt:
        intent = self._compile(action)
        if isinstance(intent, Attempt):
            return intent

        principal = self.principal or Principal(
            id="planner", kind=PrincipalKind.AGENT, workflow_id=self.workflow_id
        )

        # Scope, enforced here rather than only in the planner. The planner validates its
        # own output against the run's scope, and that check is worth having - but it is a
        # check the planner performs on itself, so a compromised planner simply does not
        # perform it. The adversarial suite found exactly that: an AdversarialPlanner
        # emitting an out-of-scope read reached a backend, because the only thing standing
        # in its way was a validator it had no reason to run. A control that lives solely
        # inside the component it constrains is not a control.
        if not self._in_scope(state, action.resource):
            state.record_denial(f"{action.tool}.{action.operation}: resource out of scope")
            return Attempt(
                action=action,
                stage=Stage.OUT_OF_SCOPE,
                reason=f"{action.resource!r} is outside the run's assigned scope",
            )

        canonical = canonicalize(principal, intent, workflow_id=self.workflow_id)

        decision = await self.policy.evaluate(
            AuthorizationRequest(
                principal=principal,
                intent=intent,
                requested_at=dt.datetime.now(dt.UTC),
                environment=self.environment,
                registry_hash=self.registry.hash,
                untrusted_context_count=state.untrusted_count,
            )
        )

        if (
            not decision.permits_execution
            and decision.outcome is not PolicyOutcome.REQUIRE_APPROVAL
        ):
            state.record_denial(f"{intent.qualified_name}: {decision.reason_code}")
            return Attempt(
                action=action,
                stage=Stage.POLICY_DENIED,
                reason=decision.reason_code,
                action_digest=canonical.digest,
            )

        # Approval is required when *either* the policy asks for one or the registry
        # declares the operation needs one. The registry is authoritative (AS-013), and an
        # earlier version of this method consulted only the policy - which meant a policy
        # that was misconfigured, compromised, or simply returned ALLOW would let an
        # irreversible operation through with no human in the loop. Two independent sources
        # have to agree that an action is safe before it proceeds without one.
        definition = self.registry.lookup(intent.tool, intent.operation)
        needs_approval = (
            definition.requires_approval or decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
        )
        if needs_approval and canonical.digest not in self.approved_digests:
            state.record_denial(f"{intent.qualified_name}: awaiting human approval")
            return Attempt(
                action=action,
                stage=Stage.APPROVAL_REQUIRED,
                reason="no approval for this exact action",
                action_digest=canonical.digest,
            )

        if self.minter is None:
            return Attempt(
                action=action,
                stage=Stage.GATEWAY_DENIED,
                reason="no capability minter configured",
                action_digest=canonical.digest,
            )

        # Policy is re-run implicitly by having reached here with a fresh decision; the
        # capability is minted against *this* digest, so any mutation after this point
        # produces a different digest and the gateway rejects the binding.
        request_hash = compute_request_hash(dict(canonical.payload["arguments"]))
        token = self.minter.mint(
            subject=principal.id,
            audience="agentsec-gateway",
            environment=self.environment,
            workflow_id=self.workflow_id,
            action_digest=canonical.digest,
            request_hash=request_hash,
            tool=intent.tool,
            resource=str(intent.resource),
            scopes=self._scopes(intent),
            ttl_seconds=self.capability_ttl_seconds,
            registry_hash=self.registry.hash,
        )

        result = await self.gateway.dispatch(
            DispatchRequest(
                principal=principal,
                intent=intent,
                workflow_id=self.workflow_id,
                capability_token=token,
                operation_id=operation_id(self.workflow_id, canonical.digest, occurrence),
                run_id=state.run_id,
            )
        )
        return self._as_attempt(action, canonical.digest, result)

    def _compile(self, action: ProposedAction) -> ActionIntent | Attempt:
        """Turn a proposal into an intent using the trusted registry.

        The registry supplies the risk class. A planner that could name its own would be
        able to declare a secret read low-risk, which is the whole game.
        """
        try:
            definition = self.registry.lookup(action.tool, action.operation)
        except UnknownToolError as error:
            return Attempt(action=action, stage=Stage.UNKNOWN_TOOL, reason=str(error))

        try:
            scheme, _, identifier = action.resource.partition("://")
            intent = ActionIntent(
                tool=action.tool,
                operation=action.operation,
                resource=ResourceRef(scheme=scheme, identifier=identifier),
                arguments=action.arguments,
                risk_class=definition.risk_class,
            )
        except Exception as error:  # pydantic validation, resource normalisation
            return Attempt(
                action=action,
                stage=Stage.INVALID_ACTION,
                reason=f"{type(error).__name__}: {error}"[:300],
            )
        return intent

    @staticmethod
    def _as_attempt(action: ProposedAction, digest: str, result: GatewayResult) -> Attempt:
        if result.ok:
            return Attempt(
                action=action,
                stage=Stage.EXECUTED,
                action_digest=digest,
                reached_backend=result.reached_backend,
                result=result.result.payload if result.result else None,
            )
        return Attempt(
            action=action,
            stage=Stage.GATEWAY_DENIED,
            reason=result.denial.value if result.denial else "unknown",
            action_digest=digest,
            reached_backend=result.reached_backend,
        )

    @staticmethod
    def _in_scope(state: SecurityAgentState, resource: str) -> bool:
        """Whether a resource is inside the run's assignment.

        An empty scope means unrestricted, which is only ever the case in tests that are
        exercising something else; a real run always carries one.
        """
        if not state.resource_scope:
            return True
        return any(resource.startswith(prefix) for prefix in state.resource_scope)

    def _scopes(self, intent: ActionIntent) -> Sequence[str]:
        definition = self.registry.lookup(intent.tool, intent.operation)
        return definition.required_scopes


def new_run_id() -> str:
    return f"run-{uuid.uuid4().hex[:12]}"


__all__ = ["Attempt", "ControlOutcome", "ControlPipeline", "Planner", "Stage", "new_run_id"]
