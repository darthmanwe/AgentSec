"""MCP Gateway tests (AS-014).

The assertion that matters is ``backend.call_count == 0``. Every denial test makes it,
because "the gateway returned an error" and "the backend was never told about this" are
different claims, and only the second is a security property.

This is what AS-012 could not assert — there was no gateway, so there was no backend to
observe. The rev-2 amendment moved those assertions here.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentsec.authz.capabilities import (
    CapabilityMinter,
    CapabilityRedeemer,
    CapabilityVerifier,
    compute_request_hash,
)
from agentsec.authz.digest import canonicalize
from agentsec.authz.keys import SigningKey, VerificationKeyring
from agentsec.authz.models import (
    ActionIntent,
    Principal,
    PrincipalKind,
    ResourceRef,
    RiskClass,
    TrustLevel,
)
from agentsec.db.base import Base
from agentsec.gateway.core import (
    DispatchRequest,
    GatewayDenial,
    GatewayResult,
    InMemoryAuditSink,
    McpGateway,
    RecordingBackend,
)
from agentsec.gateway.registry import ToolDefinition, ToolRegistry, load_registry

pytestmark = pytest.mark.authz

START = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.UTC)
PLANNER = Principal(id="planner", kind=PrincipalKind.AGENT, workflow_id="wf-1", run_id="run-1")
REGISTRY = load_registry()


class MovableClock:
    def __init__(self, start: dt.datetime) -> None:
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += dt.timedelta(**kwargs)


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
def clock() -> MovableClock:
    return MovableClock(START)


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())


@pytest.fixture
def backend() -> RecordingBackend:
    return RecordingBackend(
        responses={"fixture_repo.read_file": {"content": "print('hello')", "lines": 1}}
    )


@pytest.fixture
def audit() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def minter(signing_key: SigningKey, clock: MovableClock) -> CapabilityMinter:
    return CapabilityMinter(signing_key, clock=clock)


@pytest.fixture
def gateway(
    signing_key: SigningKey,
    clock: MovableClock,
    backend: RecordingBackend,
    audit: InMemoryAuditSink,
    session: AsyncSession,
) -> McpGateway:
    return McpGateway(
        registry=REGISTRY,
        verifier=CapabilityVerifier(
            VerificationKeyring.of(signing_key.kid, signing_key.public_key), clock=clock
        ),
        redeemer=CapabilityRedeemer(session),
        backends={"fixture_repo": backend, "fake_jira": backend},
        audit=audit,
    )


def read_intent(**overrides: Any) -> ActionIntent:
    base = ActionIntent(
        tool="fixture_repo",
        operation="read_file",
        resource=ResourceRef(scheme="fixture", identifier="repo-a/src/main.py"),
        arguments={"path": "src/main.py"},
        risk_class=RiskClass.READ_ONLY,
    )
    return base.model_copy(update=overrides) if overrides else base


def mint_for(
    minter: CapabilityMinter,
    intent: ActionIntent,
    *,
    scopes: tuple[str, ...] = ("repo:read",),
    registry_hash: str | None = None,
) -> str:
    action = canonicalize(PLANNER, intent, workflow_id="wf-1")
    return minter.mint(
        subject=PLANNER.id,
        audience="agentsec-gateway",
        environment="local",
        workflow_id="wf-1",
        action_digest=action.digest,
        request_hash=compute_request_hash(action.arguments),
        tool=intent.tool,
        resource=intent.resource.uri,
        scopes=scopes,
        ttl_seconds=60,
        registry_hash=registry_hash if registry_hash is not None else REGISTRY.hash,
    )


def request_for(
    intent: ActionIntent, token: str | None, operation_id: str = "op-1"
) -> DispatchRequest:
    return DispatchRequest(
        principal=PLANNER,
        intent=intent,
        workflow_id="wf-1",
        capability_token=token,
        operation_id=operation_id,
        run_id="run-1",
    )


# --------------------------------------------------------------------------- happy path


async def test_an_authorized_read_reaches_the_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    """The control case. Without it, every "zero calls" assertion below could pass
    because the gateway never works at all."""
    intent = read_intent()
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))

    assert result.ok is True
    assert result.reached_backend is True
    assert backend.call_count == 1
    assert result.result is not None
    assert result.result.payload["content"] == "print('hello')"


async def test_results_carry_an_untrusted_label(
    gateway: McpGateway, minter: CapabilityMinter
) -> None:
    """Nothing a backend returns is trusted. The label travels with the value so the
    planner's context cannot lose track of where it came from."""
    intent = read_intent()
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.result is not None
    assert result.result.trust is TrustLevel.UNTRUSTED


async def test_dispatch_sends_the_canonical_arguments(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    """What was hashed is what is sent. Dispatching the caller's original input instead
    would make every binding above apply to bytes that never reached the backend."""
    intent = read_intent(arguments={"path": "src/café.py"})
    await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    _tool, _operation, arguments = backend.calls[0]
    assert arguments["path"] == "src/café.py"


# ------------------------------------------------- denials never reach the backend


async def test_unknown_tool_never_reaches_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    intent = read_intent()
    token = mint_for(minter, intent)
    unknown = intent.model_copy(update={"tool": "mystery_tool"})

    result = await gateway.dispatch(request_for(unknown, token))
    assert result.denial is GatewayDenial.UNKNOWN_TOOL
    assert result.reached_backend is False
    assert backend.call_count == 0


async def test_unknown_operation_never_reaches_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    intent = read_intent(operation="exfiltrate")
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.denial is GatewayDenial.UNKNOWN_TOOL
    assert backend.call_count == 0


async def test_wrong_scheme_never_reaches_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    """The confused-deputy case, enforced a second time at the gateway. Policy checks it
    too; defence in depth is the point."""
    intent = read_intent(resource=ResourceRef(scheme="jira", identifier="PROJ"))
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.denial is GatewayDenial.SCHEME_NOT_PERMITTED
    assert backend.call_count == 0


async def test_invalid_arguments_never_reach_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    intent = read_intent(arguments={"wrong_field": "x"})
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.denial is GatewayDenial.INVALID_ARGUMENTS
    assert backend.call_count == 0


async def test_extra_arguments_are_rejected(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    """additionalProperties: false in the registry schema. An unexpected argument is
    either a version mismatch or an injection attempt."""
    intent = read_intent(arguments={"path": "src/main.py", "sudo": True})
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.denial is GatewayDenial.INVALID_ARGUMENTS
    assert backend.call_count == 0


async def test_no_capability_never_reaches_a_backend(
    gateway: McpGateway, backend: RecordingBackend
) -> None:
    result = await gateway.dispatch(request_for(read_intent(), None))
    assert result.denial is GatewayDenial.NO_CAPABILITY
    assert backend.call_count == 0


async def test_capability_for_a_different_action_never_reaches_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    """Mint for one file, dispatch for another. The digest differs, so the grant does not
    apply — this is argument mutation after authorization, at the last possible moment."""
    token = mint_for(minter, read_intent())
    other = read_intent(arguments={"path": "src/secrets.py"})

    result = await gateway.dispatch(request_for(other, token))
    assert result.denial is GatewayDenial.CAPABILITY_REJECTED
    assert backend.call_count == 0


async def test_expired_capability_never_reaches_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend, clock: MovableClock
) -> None:
    intent = read_intent()
    token = mint_for(minter, intent)
    clock.advance(seconds=120)

    result = await gateway.dispatch(request_for(intent, token))
    assert result.denial is GatewayDenial.CAPABILITY_REJECTED
    assert backend.call_count == 0


async def test_forged_capability_never_reaches_a_backend(
    gateway: McpGateway, clock: MovableClock, backend: RecordingBackend
) -> None:
    attacker = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())
    intent = read_intent()
    token = mint_for(CapabilityMinter(attacker, clock=clock), intent)

    result = await gateway.dispatch(request_for(intent, token))
    assert result.denial is GatewayDenial.CAPABILITY_REJECTED
    assert backend.call_count == 0


async def test_stale_registry_hash_never_reaches_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    """A grant minted against a different registry is refused: risk classifications may
    have moved since, so the authorization behind it no longer describes reality."""
    intent = read_intent()
    token = mint_for(minter, intent, registry_hash="f" * 64)

    result = await gateway.dispatch(request_for(intent, token))
    assert result.denial is GatewayDenial.CAPABILITY_REJECTED
    assert backend.call_count == 0


async def test_replayed_capability_reaches_the_backend_exactly_once(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    intent = read_intent()
    token = mint_for(minter, intent)

    first = await gateway.dispatch(request_for(intent, token, operation_id="op-1"))
    assert first.ok is True
    assert backend.call_count == 1

    replay = await gateway.dispatch(request_for(intent, token, operation_id="op-2"))
    assert replay.denial is GatewayDenial.REPLAYED
    assert replay.reached_backend is False
    assert backend.call_count == 1, "a replayed capability reached the backend a second time"


async def test_missing_scope_never_reaches_a_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend
) -> None:
    intent = read_intent()
    token = mint_for(minter, intent, scopes=("jira:read",))
    result = await gateway.dispatch(request_for(intent, token))
    assert result.denial is GatewayDenial.CAPABILITY_REJECTED
    assert backend.call_count == 0


# --------------------------------------------------------------------------- backend


async def test_timeout_denies_and_is_reported_as_reaching_the_backend(
    signing_key: SigningKey,
    clock: MovableClock,
    minter: CapabilityMinter,
    audit: InMemoryAuditSink,
    session: AsyncSession,
) -> None:
    """A slow backend is a failed dispatch, not a hang.

    Uses a purpose-built registry with a 50ms timeout rather than sleeping past the
    shipped 10s one - a test that takes ten seconds is a test people start skipping.
    """
    fast_registry = ToolRegistry(
        [
            ToolDefinition.model_validate(
                {
                    "tool": "fixture_repo",
                    "operation": "read_file",
                    "description": "Read a file.",
                    "risk_class": "read_only",
                    "resource_schemes": ["fixture"],
                    "required_scopes": ["repo:read"],
                    "requires_approval": False,
                    "idempotent": True,
                    "result_trust": "untrusted",
                    "timeout_seconds": 0.05,
                    "max_result_bytes": 1024,
                }
            )
        ],
        version="test",
    )
    slow = RecordingBackend(delay_seconds=2.0)
    gateway = McpGateway(
        registry=fast_registry,
        verifier=CapabilityVerifier(
            VerificationKeyring.of(signing_key.kid, signing_key.public_key), clock=clock
        ),
        redeemer=CapabilityRedeemer(session),
        backends={"fixture_repo": slow},
        audit=audit,
    )
    intent = read_intent()
    action = canonicalize(PLANNER, intent, workflow_id="wf-1")
    token = minter.mint(
        subject=PLANNER.id,
        audience="agentsec-gateway",
        environment="local",
        workflow_id="wf-1",
        action_digest=action.digest,
        request_hash=compute_request_hash(action.arguments),
        tool=intent.tool,
        resource=intent.resource.uri,
        scopes=("repo:read",),
        ttl_seconds=60,
        registry_hash=fast_registry.hash,
    )

    result = await gateway.dispatch(request_for(intent, token))

    assert result.ok is False
    assert result.denial is GatewayDenial.TIMEOUT
    # The backend WAS reached - a timeout is a different claim from a denial before
    # dispatch, and the audit trail has to be able to tell them apart.
    assert result.reached_backend is True
    assert slow.call_count == 1
    assert audit.of_type("gateway.denied")[0]["reached_backend"] is True


async def test_backend_error_is_contained(
    signing_key: SigningKey,
    clock: MovableClock,
    minter: CapabilityMinter,
    audit: InMemoryAuditSink,
    session: AsyncSession,
) -> None:
    """A backend blowing up is a failed dispatch, not an exception escaping the gateway."""
    broken = RecordingBackend(raises=RuntimeError("backend exploded"))
    gateway = McpGateway(
        registry=REGISTRY,
        verifier=CapabilityVerifier(
            VerificationKeyring.of(signing_key.kid, signing_key.public_key), clock=clock
        ),
        redeemer=CapabilityRedeemer(session),
        backends={"fixture_repo": broken},
        audit=audit,
    )
    intent = read_intent()
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.ok is False
    assert result.denial is GatewayDenial.BACKEND_ERROR
    assert result.reached_backend is True


async def test_oversized_result_is_refused_not_truncated(
    signing_key: SigningKey,
    clock: MovableClock,
    minter: CapabilityMinter,
    audit: InMemoryAuditSink,
    session: AsyncSession,
) -> None:
    """Refused rather than truncated: a silently shortened result is a lie the planner
    would reason over."""
    huge = RecordingBackend(responses={"fixture_repo.read_file": {"content": "x" * 2_000_000}})
    gateway = McpGateway(
        registry=REGISTRY,
        verifier=CapabilityVerifier(
            VerificationKeyring.of(signing_key.kid, signing_key.public_key), clock=clock
        ),
        redeemer=CapabilityRedeemer(session),
        backends={"fixture_repo": huge},
        audit=audit,
    )
    intent = read_intent()
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.denial is GatewayDenial.OVERSIZED_RESULT
    assert result.result is None, "an oversized result must not be returned at all"


async def test_no_backend_registered_is_a_denial(
    signing_key: SigningKey,
    clock: MovableClock,
    minter: CapabilityMinter,
    audit: InMemoryAuditSink,
    session: AsyncSession,
) -> None:
    gateway = McpGateway(
        registry=REGISTRY,
        verifier=CapabilityVerifier(
            VerificationKeyring.of(signing_key.kid, signing_key.public_key), clock=clock
        ),
        redeemer=CapabilityRedeemer(session),
        backends={},
        audit=audit,
    )
    intent = read_intent()
    result = await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    assert result.denial is GatewayDenial.NO_BACKEND
    assert result.reached_backend is False


# --------------------------------------------------------------------------- audit


async def test_successful_dispatch_is_audited(
    gateway: McpGateway, minter: CapabilityMinter, audit: InMemoryAuditSink
) -> None:
    intent = read_intent()
    await gateway.dispatch(request_for(intent, mint_for(minter, intent)))
    (event,) = audit.of_type("gateway.dispatch")
    assert event["outcome"] == "EXECUTED"
    assert event["tool"] == "fixture_repo"
    assert event["trust_label"] == "untrusted"
    assert len(event["action_digest"]) == 64


async def test_denial_is_audited_with_its_reason(
    gateway: McpGateway, audit: InMemoryAuditSink
) -> None:
    """Denials are evidence, not noise. An unauthorized attempt that left no record would
    be invisible to the metric the project reports."""
    await gateway.dispatch(request_for(read_intent(), None))
    (event,) = audit.of_type("gateway.denied")
    assert event["outcome"] == "DENIED"
    assert event["denial"] == GatewayDenial.NO_CAPABILITY.value
    assert event["reached_backend"] is False


async def test_every_attempt_is_audited_whatever_the_outcome(
    gateway: McpGateway, minter: CapabilityMinter, audit: InMemoryAuditSink
) -> None:
    intent = read_intent()
    await gateway.dispatch(request_for(intent, mint_for(minter, intent), operation_id="op-a"))
    await gateway.dispatch(request_for(intent, None, operation_id="op-b"))
    await gateway.dispatch(request_for(read_intent(tool="mystery"), None, operation_id="op-c"))
    assert len(audit.events) == 3


# --------------------------------------------------------------------------- sweep


async def test_no_denial_path_reaches_the_backend(
    gateway: McpGateway, minter: CapabilityMinter, backend: RecordingBackend, clock: MovableClock
) -> None:
    """Swept assertion over every denial at once.

    Individually-passing tests can still leave a path open if one case is forgotten. This
    runs the whole set against a single recording backend and requires it never to have
    been called.
    """
    intent = read_intent()
    good = mint_for(minter, intent)
    attacker = SigningKey(kid="k1", private_key=Ed25519PrivateKey.generate())

    attempts = [
        request_for(read_intent(tool="mystery_tool"), good, "a"),
        request_for(read_intent(operation="exfiltrate"), good, "b"),
        request_for(read_intent(arguments={"nope": 1}), good, "c"),
        request_for(read_intent(arguments={"path": "x", "sudo": True}), good, "d"),
        request_for(intent, None, "e"),
        request_for(read_intent(arguments={"path": "other.py"}), good, "f"),
        request_for(intent, mint_for(CapabilityMinter(attacker, clock=clock), intent), "g"),
        request_for(intent, mint_for(minter, intent, scopes=("wrong:scope",)), "h"),
        request_for(intent, mint_for(minter, intent, registry_hash="f" * 64), "i"),
        request_for(read_intent(resource=ResourceRef(scheme="jira", identifier="P")), good, "j"),
    ]

    for attempt in attempts:
        result = await gateway.dispatch(attempt)
        assert result.ok is False, f"attempt {attempt.operation_id} was permitted"
        assert result.reached_backend is False

    assert backend.call_count == 0, "a denial path reached the backend"


# --------------------------------------------------------------------------- result type


def test_result_cannot_claim_a_backend_call_it_did_not_make() -> None:
    """Structural guard: only failures that happen *at* the backend may report reaching
    it. Anything else claiming so would mean an authorization failure let a call through."""
    with pytest.raises(ValueError, match="must not report reaching the backend"):
        GatewayResult(ok=False, denial=GatewayDenial.NO_CAPABILITY, reached_backend=True)


def test_result_cannot_be_incoherent() -> None:
    with pytest.raises(ValueError, match="cannot carry a denial"):
        GatewayResult(ok=True, denial=GatewayDenial.TIMEOUT)
    with pytest.raises(ValueError, match="must say why"):
        GatewayResult(ok=False)
