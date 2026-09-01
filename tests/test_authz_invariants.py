"""Authorization security invariant suite (AS-012).

The individual modules each test their own rules. This file tests the **composition**: it
wires policy, approval, minting, verification and redemption into the pipeline the gateway
will use, then drives attacks through the whole thing.

That distinction matters. Every component can be individually correct while the assembly
leaks — the confused-deputy gap in AS-009 was exactly that, and it survived a green unit
suite. Here the question is never "does this function reject bad input" but "can an
attacker get an unauthorized action all the way to the point of execution".

Scope is kernel-only. End-to-end "zero backend calls" assertions need a gateway and belong
to AS-014; there is no backend to observe yet.

**Everything here runs with no model and no network.**
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentsec.authz.approvals import ApprovalService, as_aware
from agentsec.authz.capabilities import (
    CapabilityDenial,
    CapabilityMinter,
    CapabilityRedeemer,
    CapabilityVerifier,
    ExpectedBinding,
    compute_request_hash,
)
from agentsec.authz.digest import canonicalize
from agentsec.authz.engine import DenyAllPolicyEngine
from agentsec.authz.keys import SigningKey, VerificationKeyring
from agentsec.authz.models import (
    ActionIntent,
    AuthorizationRequest,
    PolicyDecision,
    PolicyOutcome,
    Principal,
    PrincipalKind,
    ResourceRef,
    RiskClass,
)
from agentsec.db.base import Base
from agentsec.db.models import Approval, Run, RunStatus

pytestmark = pytest.mark.authz

START = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.UTC)
PLANNER = Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1", run_id="run-1")
OPERATOR = Principal(id="alice", kind=PrincipalKind.OPERATOR)


class MovableClock:
    def __init__(self, start: dt.datetime) -> None:
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += dt.timedelta(**kwargs)


class ScriptedPolicyEngine:
    """Returns a canned decision. Keeps the suite offline and deterministic.

    The real Rego bundle is exercised against live OPA in test_policy_bundle.py; here the
    question is what the *kernel* does with a decision, not what the policy decides.
    """

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.calls = 0

    async def evaluate(self, request: AuthorizationRequest) -> PolicyDecision:
        self.calls += 1
        return self.decision


def allow() -> PolicyDecision:
    return PolicyDecision(outcome=PolicyOutcome.ALLOW, reason_code="read_permitted")


def require_approval() -> PolicyDecision:
    return PolicyDecision(
        outcome=PolicyOutcome.REQUIRE_APPROVAL,
        reason_code="mutating_operation_requires_approval",
    )


def deny(reason: str = "default_deny") -> PolicyDecision:
    return PolicyDecision(outcome=PolicyOutcome.DENY, reason_code=reason)


@dataclass
class KernelOutcome:
    """What the pipeline decided, and how far the request got."""

    permitted: bool
    stage: str
    reason: str
    token: str | None = None
    redeemed: bool = False


@dataclass
class AuthorizationKernel:
    """The S1 primitives wired into the order the gateway will use them.

    Deliberately small and explicit. AS-014 builds the production path; this exists so the
    invariants can be asserted against a composition before a gateway exists to hide them.
    """

    policy: ScriptedPolicyEngine
    approvals: ApprovalService
    session: AsyncSession
    minter: CapabilityMinter
    verifier: CapabilityVerifier
    redeemer: CapabilityRedeemer
    clock: MovableClock
    audience: str = "agentsec-gateway"
    environment: str = "local"
    attempts: list[KernelOutcome] = field(default_factory=list)

    async def authorize(
        self,
        intent: ActionIntent,
        *,
        principal: Principal = PLANNER,
        run_id: str = "run-1",
        workflow_id: str = "wf-1",
        scopes: tuple[str, ...] = ("tool:invoke",),
    ) -> KernelOutcome:
        """Run one action through policy, approval and capability minting."""
        action = canonicalize(principal, intent, workflow_id=workflow_id)

        request = AuthorizationRequest(
            principal=principal, intent=intent, requested_at=self.clock()
        )
        decision = await self.policy.evaluate(request)

        if decision.outcome is PolicyOutcome.DENY:
            return self._record(False, "policy", decision.reason_code)

        approval_expires_at = None
        if decision.outcome is PolicyOutcome.REQUIRE_APPROVAL:
            resolution = await self.approvals.resolve(action_digest=action.digest, run_id=run_id)
            if not resolution.permitted:
                return self._record(False, "approval", resolution.reason.value)
            approval = await self.session.get(Approval, resolution.approval_id)
            # The grant must not outlive the approval behind it (AS-011).
            approval_expires_at = as_aware(approval.expires_at) if approval else None

        token = self.minter.mint(
            subject=principal.id,
            audience=self.audience,
            environment=self.environment,
            workflow_id=workflow_id,
            action_digest=action.digest,
            request_hash=compute_request_hash(action.arguments),
            tool=intent.tool,
            resource=intent.resource.uri,
            scopes=scopes,
            ttl_seconds=60,
            approval_expires_at=approval_expires_at,
        )
        return self._record(True, "minted", "capability_issued", token=token)

    async def execute(
        self,
        outcome: KernelOutcome,
        intent: ActionIntent,
        *,
        principal: Principal = PLANNER,
        workflow_id: str = "wf-1",
        operation_id: str = "op-1",
        scopes: tuple[str, ...] = ("tool:invoke",),
    ) -> KernelOutcome:
        """Verify and redeem, as the gateway would immediately before dispatch."""
        if outcome.token is None:
            return outcome

        action = canonicalize(principal, intent, workflow_id=workflow_id)
        expected = ExpectedBinding(
            subject=principal.id,
            audience=self.audience,
            environment=self.environment,
            workflow_id=workflow_id,
            action_digest=action.digest,
            request_hash=compute_request_hash(action.arguments),
            tool=intent.tool,
            resource=intent.resource.uri,
            required_scopes=scopes,
        )
        result = self.verifier.verify(outcome.token, expected)
        if not result.ok:
            assert result.denial is not None
            return self._record(False, "capability", result.denial.value, token=outcome.token)

        assert result.claims is not None
        if not await self.redeemer.redeem(result.claims, operation_id=operation_id):
            return self._record(
                False, "redemption", CapabilityDenial.REPLAYED.value, token=outcome.token
            )
        return self._record(True, "executed", "authorized", token=outcome.token, redeemed=True)

    def _record(
        self,
        permitted: bool,
        stage: str,
        reason: str,
        *,
        token: str | None = None,
        redeemed: bool = False,
    ) -> KernelOutcome:
        outcome = KernelOutcome(permitted, stage, reason, token, redeemed)
        self.attempts.append(outcome)
        return outcome


# --------------------------------------------------------------------------- fixtures


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        s.add(
            Run(
                id="run-1",
                workflow_id="wf-1",
                status=RunStatus.AUTHORIZING,
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


def build_kernel(
    session: AsyncSession, clock: MovableClock, decision: PolicyDecision
) -> AuthorizationKernel:
    key = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())
    return AuthorizationKernel(
        policy=ScriptedPolicyEngine(decision),
        approvals=ApprovalService(session, clock=clock),
        session=session,
        minter=CapabilityMinter(key, clock=clock),
        verifier=CapabilityVerifier(VerificationKeyring.of(key.kid, key.public_key), clock=clock),
        redeemer=CapabilityRedeemer(session),
        clock=clock,
    )


def read_intent() -> ActionIntent:
    return ActionIntent(
        tool="fixture_repo",
        operation="read_file",
        resource=ResourceRef(scheme="fixture", identifier="repo-a/src/main.py"),
        arguments={"path": "src/main.py"},
        risk_class=RiskClass.READ_ONLY,
    )


def write_intent(**arguments: object) -> ActionIntent:
    return ActionIntent(
        tool="fake_jira",
        operation="create_issue",
        resource=ResourceRef(scheme="jira", identifier="PROJ"),
        arguments=arguments or {"summary": "Fix SQLi in login"},
        risk_class=RiskClass.HIGH_RISK_WRITE,
    )


# --------------------------------------------------------------------------- baseline


async def test_a_permitted_read_completes(session: AsyncSession, clock: MovableClock) -> None:
    """The control case. If this failed, every denial below would be meaningless."""
    kernel = build_kernel(session, clock, allow())
    intent = read_intent()
    outcome = await kernel.execute(await kernel.authorize(intent), intent)
    assert outcome.permitted is True
    assert outcome.redeemed is True


async def test_an_approved_mutation_completes(session: AsyncSession, clock: MovableClock) -> None:
    kernel = build_kernel(session, clock, require_approval())
    intent = write_intent()
    action = canonicalize(PLANNER, intent, workflow_id="wf-1")

    approval = await kernel.approvals.create(run_id="run-1", action_digest=action.digest)
    await kernel.approvals.decide(approval.id, approver=OPERATOR, approved=True)

    outcome = await kernel.execute(await kernel.authorize(intent), intent)
    assert outcome.permitted is True
    assert outcome.redeemed is True


# --------------------------------------------------------------------------- invariants


async def test_policy_denial_stops_before_minting(
    session: AsyncSession, clock: MovableClock
) -> None:
    kernel = build_kernel(session, clock, deny("unknown_tool"))
    outcome = await kernel.authorize(read_intent())
    assert outcome.permitted is False
    assert outcome.stage == "policy"
    assert outcome.token is None, "no capability may be minted for a denied action"


async def test_policy_engine_outage_stops_before_minting(
    session: AsyncSession, clock: MovableClock
) -> None:
    """The fail-closed path, composed. An unreachable engine must not merely log a warning
    somewhere upstream — it must stop the pipeline."""
    kernel = build_kernel(session, clock, deny())
    kernel.policy = ScriptedPolicyEngine(
        await DenyAllPolicyEngine().evaluate(
            AuthorizationRequest(principal=PLANNER, intent=read_intent(), requested_at=START)
        )
    )
    outcome = await kernel.authorize(read_intent())
    assert outcome.permitted is False
    assert outcome.token is None


async def test_mutation_without_approval_never_mints(
    session: AsyncSession, clock: MovableClock
) -> None:
    kernel = build_kernel(session, clock, require_approval())
    outcome = await kernel.authorize(write_intent())
    assert outcome.permitted is False
    assert outcome.stage == "approval"
    assert outcome.reason == "approval_not_found"
    assert outcome.token is None


async def test_argument_mutation_after_approval_invalidates_it(
    session: AsyncSession, clock: MovableClock
) -> None:
    """The headline invariant of the whole approval design.

    An operator approves one exact action. Changing a single argument changes the digest
    (AS-007), so the mutated action finds no approval — it does not "mostly match".
    """
    kernel = build_kernel(session, clock, require_approval())
    approved = write_intent(summary="Fix SQLi in login")
    action = canonicalize(PLANNER, approved, workflow_id="wf-1")

    approval = await kernel.approvals.create(run_id="run-1", action_digest=action.digest)
    await kernel.approvals.decide(approval.id, approver=OPERATOR, approved=True)

    mutated = write_intent(summary="Fix SQLi in login", assignee="attacker")
    outcome = await kernel.authorize(mutated)
    assert outcome.permitted is False
    assert outcome.stage == "approval"
    assert outcome.token is None


async def test_denied_approval_never_mints(session: AsyncSession, clock: MovableClock) -> None:
    kernel = build_kernel(session, clock, require_approval())
    intent = write_intent()
    action = canonicalize(PLANNER, intent, workflow_id="wf-1")

    approval = await kernel.approvals.create(run_id="run-1", action_digest=action.digest)
    await kernel.approvals.decide(approval.id, approver=OPERATOR, approved=False)

    outcome = await kernel.authorize(intent)
    assert outcome.permitted is False
    assert outcome.reason == "approval_denied_by_operator"


async def test_expired_approval_never_mints(session: AsyncSession, clock: MovableClock) -> None:
    kernel = build_kernel(session, clock, require_approval())
    intent = write_intent()
    action = canonicalize(PLANNER, intent, workflow_id="wf-1")

    approval = await kernel.approvals.create(
        run_id="run-1", action_digest=action.digest, ttl_seconds=60
    )
    await kernel.approvals.decide(approval.id, approver=OPERATOR, approved=True)
    clock.advance(seconds=120)

    outcome = await kernel.authorize(intent)
    assert outcome.permitted is False
    assert outcome.reason == "approval_expired"


async def test_expired_capability_does_not_execute(
    session: AsyncSession, clock: MovableClock
) -> None:
    """Authority granted is not authority retained. A grant that lapsed between minting and
    dispatch is refused at the point of use."""
    kernel = build_kernel(session, clock, allow())
    intent = read_intent()
    minted = await kernel.authorize(intent)
    clock.advance(seconds=90)

    outcome = await kernel.execute(minted, intent)
    assert outcome.permitted is False
    assert outcome.reason == CapabilityDenial.EXPIRED.value


async def test_capability_cannot_be_aimed_at_a_different_action(
    session: AsyncSession, clock: MovableClock
) -> None:
    """Mint for a read, then present the grant while dispatching a write."""
    kernel = build_kernel(session, clock, allow())
    minted = await kernel.authorize(read_intent())

    outcome = await kernel.execute(minted, write_intent())
    assert outcome.permitted is False
    assert outcome.reason in {
        CapabilityDenial.WRONG_TOOL.value,
        CapabilityDenial.WRONG_DIGEST.value,
        CapabilityDenial.WRONG_RESOURCE.value,
    }


async def test_capability_replay_is_rejected(session: AsyncSession, clock: MovableClock) -> None:
    kernel = build_kernel(session, clock, allow())
    intent = read_intent()
    minted = await kernel.authorize(intent)

    first = await kernel.execute(minted, intent, operation_id="op-1")
    assert first.permitted is True

    replay = await kernel.execute(minted, intent, operation_id="op-2")
    assert replay.permitted is False
    assert replay.reason == CapabilityDenial.REPLAYED.value


async def test_tampered_capability_is_rejected(session: AsyncSession, clock: MovableClock) -> None:
    import base64
    import json

    kernel = build_kernel(session, clock, allow())
    intent = read_intent()
    minted = await kernel.authorize(intent)
    assert minted.token is not None

    body_b64, signature_b64 = minted.token.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(body_b64 + "=="))
    payload["scopes"] = ["tool:invoke", "admin:everything"]
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    outcome = await kernel.execute(
        KernelOutcome(True, "minted", "x", token=f"{forged}.{signature_b64}"), intent
    )
    assert outcome.permitted is False
    assert outcome.reason == CapabilityDenial.BAD_SIGNATURE.value


async def test_an_agent_cannot_approve_its_own_action(
    session: AsyncSession, clock: MovableClock
) -> None:
    """Self-authorization, attempted directly. The clause of the invariant that the whole
    project exists to enforce."""
    from agentsec.authz.approvals import ApprovalError

    kernel = build_kernel(session, clock, require_approval())
    intent = write_intent()
    action = canonicalize(PLANNER, intent, workflow_id="wf-1")
    approval = await kernel.approvals.create(run_id="run-1", action_digest=action.digest)

    with pytest.raises(ApprovalError, match="cannot approve"):
        await kernel.approvals.decide(approval.id, approver=PLANNER, approved=True)

    assert (await kernel.authorize(intent)).permitted is False


# --------------------------------------------------------------------------- sweep


async def test_no_attack_scenario_reaches_execution(
    session: AsyncSession, clock: MovableClock
) -> None:
    """The AS-028B pattern in miniature: run every attack, then assert the aggregate.

    Individually-passing denial tests can still leave a path open if one scenario is
    forgotten. This counts executions across the whole set and requires zero — the same
    shape as the headline metric, at kernel scale.
    """
    attacks: list[tuple[str, PolicyDecision, ActionIntent]] = [
        ("policy denies", deny("unknown_tool"), read_intent()),
        ("secret access", deny("secret_access_always_denied"), read_intent()),
        ("engine outage", deny("policy_engine_unavailable"), read_intent()),
        ("mutation, no approval", require_approval(), write_intent()),
        ("mutation, mutated args", require_approval(), write_intent(assignee="attacker")),
    ]

    executed = 0
    attempted = 0
    for _label, decision, intent in attacks:
        kernel = build_kernel(session, clock, decision)
        attempted += 1
        outcome = await kernel.execute(await kernel.authorize(intent), intent)
        if outcome.redeemed:
            executed += 1

    assert attempted == len(attacks)
    assert executed == 0, "an attack scenario reached execution"
