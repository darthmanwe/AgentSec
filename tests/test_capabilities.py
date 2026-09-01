"""Capability grant tests (AS-011).

Every binding gets a negative test. A grant is authority to do one thing once, and each
field exists to stop one specific way of reusing it somewhere it does not belong; a field
without a test proving it is checked is decoration.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentsec.authz.capabilities import (
    MAX_TTL_SECONDS,
    MIN_TTL_SECONDS,
    CapabilityDenial,
    CapabilityError,
    CapabilityMinter,
    CapabilityRedeemer,
    CapabilityVerifier,
    ExpectedBinding,
    VerificationResult,
    compute_request_hash,
)
from agentsec.authz.keys import SigningKey, VerificationKeyring
from agentsec.db.base import Base

pytestmark = pytest.mark.authz

START = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.UTC)
DIGEST = "a" * 64
REQUEST_HASH = compute_request_hash({"issue": "PROJ-1", "body": "please review"})


class MovableClock:
    def __init__(self, start: dt.datetime) -> None:
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += dt.timedelta(**kwargs)


@pytest.fixture
def clock() -> MovableClock:
    return MovableClock(START)


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey(kid="test-key-1", private_key=Ed25519PrivateKey.generate())


@pytest.fixture
def keyring(signing_key: SigningKey) -> VerificationKeyring:
    return VerificationKeyring.of(signing_key.kid, signing_key.public_key)


@pytest.fixture
def minter(signing_key: SigningKey, clock: MovableClock) -> CapabilityMinter:
    return CapabilityMinter(signing_key, clock=clock)


@pytest.fixture
def verifier(keyring: VerificationKeyring, clock: MovableClock) -> CapabilityVerifier:
    return CapabilityVerifier(keyring, clock=clock)


def binding(**overrides: object) -> ExpectedBinding:
    defaults: dict[str, object] = {
        "subject": "planner",
        "audience": "agentsec-gateway",
        "environment": "local",
        "workflow_id": "wf-1",
        "action_digest": DIGEST,
        "request_hash": REQUEST_HASH,
        "tool": "fake_jira",
        "resource": "jira://PROJ",
        "required_scopes": ["jira:write"],
    }
    return ExpectedBinding(**{**defaults, **overrides})  # type: ignore[arg-type]


def mint(minter: CapabilityMinter, **overrides: object) -> str:
    defaults: dict[str, object] = {
        "subject": "planner",
        "audience": "agentsec-gateway",
        "environment": "local",
        "workflow_id": "wf-1",
        "action_digest": DIGEST,
        "request_hash": REQUEST_HASH,
        "tool": "fake_jira",
        "resource": "jira://PROJ",
        "scopes": ["jira:write"],
        "ttl_seconds": 60,
    }
    return minter.mint(**{**defaults, **overrides})  # type: ignore[arg-type]


# --------------------------------------------------------------------------- happy path


def test_a_correctly_bound_grant_verifies(
    minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    result = verifier.verify(mint(minter), binding())
    assert result.ok is True
    assert result.claims is not None
    assert result.claims.tool == "fake_jira"


def test_extra_scopes_on_the_grant_are_fine(
    minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    token = mint(minter, scopes=["jira:write", "jira:read"])
    assert verifier.verify(token, binding(required_scopes=["jira:write"])).ok


# --------------------------------------------------------------------------- bindings

BINDING_CASES = [
    ("subject", "someone_else", CapabilityDenial.WRONG_SUBJECT),
    ("audience", "another-gateway", CapabilityDenial.WRONG_AUDIENCE),
    ("environment", "production", CapabilityDenial.WRONG_ENVIRONMENT),
    ("workflow_id", "wf-2", CapabilityDenial.WRONG_WORKFLOW),
    ("action_digest", "b" * 64, CapabilityDenial.WRONG_DIGEST),
    ("request_hash", "c" * 64, CapabilityDenial.WRONG_REQUEST),
    ("tool", "fake_cloud", CapabilityDenial.WRONG_TOOL),
    ("resource", "jira://OTHER", CapabilityDenial.WRONG_RESOURCE),
]


@pytest.mark.parametrize(("field", "value", "denial"), BINDING_CASES)
def test_every_binding_is_enforced(
    minter: CapabilityMinter,
    verifier: CapabilityVerifier,
    field: str,
    value: str,
    denial: CapabilityDenial,
) -> None:
    """A grant valid for the action you approved must be useless for anything else."""
    result = verifier.verify(mint(minter), binding(**{field: value}))
    assert result.ok is False
    assert result.denial is denial


@pytest.mark.parametrize(("field", "value", "denial"), BINDING_CASES)
def test_binding_enforced_from_the_minting_side_too(
    minter: CapabilityMinter,
    verifier: CapabilityVerifier,
    field: str,
    value: str,
    denial: CapabilityDenial,
) -> None:
    """Same matrix, varying the grant rather than the request: a grant minted for a
    different action must not satisfy this request either."""
    token = mint(minter, **{field: value})
    result = verifier.verify(token, binding())
    assert result.ok is False
    assert result.denial is denial


def test_missing_scope_is_rejected(minter: CapabilityMinter, verifier: CapabilityVerifier) -> None:
    token = mint(minter, scopes=["jira:read"])
    result = verifier.verify(token, binding(required_scopes=["jira:write"]))
    assert result.denial is CapabilityDenial.MISSING_SCOPE


def test_stale_registry_is_rejected(minter: CapabilityMinter, verifier: CapabilityVerifier) -> None:
    """The registry changed after minting, so risk classifications may have moved and the
    authorization behind this grant no longer describes reality."""
    token = mint(minter, registry_hash="d" * 64)
    result = verifier.verify(token, binding(registry_hash="e" * 64))
    assert result.denial is CapabilityDenial.STALE_REGISTRY


def test_stale_policy_bundle_is_rejected(
    minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    token = mint(minter, policy_bundle_hash="d" * 64)
    result = verifier.verify(token, binding(policy_bundle_hash="e" * 64))
    assert result.denial is CapabilityDenial.STALE_POLICY


# --------------------------------------------------------------------------- time


def test_expired_grant_is_rejected(
    minter: CapabilityMinter, verifier: CapabilityVerifier, clock: MovableClock
) -> None:
    token = mint(minter, ttl_seconds=30)
    clock.advance(seconds=31)
    assert verifier.verify(token, binding()).denial is CapabilityDenial.EXPIRED


def test_grant_valid_right_up_to_expiry(
    minter: CapabilityMinter, verifier: CapabilityVerifier, clock: MovableClock
) -> None:
    token = mint(minter, ttl_seconds=60)
    clock.advance(seconds=59)
    assert verifier.verify(token, binding()).ok is True


def test_expiry_is_capped_by_the_approval(
    minter: CapabilityMinter, verifier: CapabilityVerifier, clock: MovableClock
) -> None:
    """A grant must never outlive the approval that authorised it, or a slow execution
    could act on authority the operator had already let lapse."""
    token = mint(minter, ttl_seconds=120, approval_expires_at=START + dt.timedelta(seconds=20))
    clock.advance(seconds=25)
    assert verifier.verify(token, binding()).denial is CapabilityDenial.EXPIRED


def test_minting_against_an_already_expired_approval_fails(minter: CapabilityMinter) -> None:
    with pytest.raises(CapabilityError, match="refusing to mint a dead grant"):
        mint(minter, approval_expires_at=START - dt.timedelta(seconds=1))


@pytest.mark.parametrize("ttl", [0, 1, 29, 121, 3600, 86400])
def test_ttl_outside_the_window_is_refused_at_mint(minter: CapabilityMinter, ttl: int) -> None:
    """Authority that outlives reasoning about it is not authority that can be audited."""
    with pytest.raises(CapabilityError, match="outside the permitted"):
        mint(minter, ttl_seconds=ttl)


@pytest.mark.parametrize("ttl", [MIN_TTL_SECONDS, 60, MAX_TTL_SECONDS])
def test_ttl_inside_the_window_is_accepted(minter: CapabilityMinter, ttl: int) -> None:
    assert mint(minter, ttl_seconds=ttl)


def test_approval_cannot_extend_a_grant_beyond_its_ttl(
    signing_key: SigningKey, keyring: VerificationKeyring
) -> None:
    """min(now + ttl, approval_expiry) caps in both directions.

    A long-lived approval must not stretch a 120s grant into a day-long one - the TTL
    bound is what keeps authority short enough to reason about.
    """
    minter = CapabilityMinter(signing_key, clock=lambda: START)
    token = minter.mint(
        subject="planner",
        audience="agentsec-gateway",
        environment="local",
        workflow_id="wf-1",
        action_digest=DIGEST,
        request_hash=REQUEST_HASH,
        tool="fake_jira",
        resource="jira://PROJ",
        scopes=["jira:write"],
        ttl_seconds=MAX_TTL_SECONDS,
        approval_expires_at=START + dt.timedelta(days=365),
    )
    fresh = CapabilityVerifier(keyring, clock=lambda: START + dt.timedelta(seconds=60))
    assert fresh.verify(token, binding()).ok is True

    lapsed = CapabilityVerifier(keyring, clock=lambda: START + dt.timedelta(seconds=121))
    assert lapsed.verify(token, binding()).denial is CapabilityDenial.EXPIRED


def test_not_yet_valid_grant_is_rejected(
    signing_key: SigningKey, keyring: VerificationKeyring
) -> None:
    future = CapabilityMinter(signing_key, clock=lambda: START + dt.timedelta(minutes=10))
    token = future.mint(
        subject="planner",
        audience="agentsec-gateway",
        environment="local",
        workflow_id="wf-1",
        action_digest=DIGEST,
        request_hash=REQUEST_HASH,
        tool="fake_jira",
        resource="jira://PROJ",
        scopes=["jira:write"],
        ttl_seconds=60,
    )
    verifier = CapabilityVerifier(keyring, clock=lambda: START)
    assert verifier.verify(token, binding()).denial is CapabilityDenial.NOT_YET_VALID


# --------------------------------------------------------------------------- crypto


def test_tampered_payload_is_rejected(
    minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    import base64
    import json

    token = mint(minter)
    body_b64, signature_b64 = token.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(body_b64 + "=="))
    payload["tool"] = "fake_cloud"
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    result = verifier.verify(f"{forged}.{signature_b64}", binding())
    assert result.denial is CapabilityDenial.BAD_SIGNATURE


def test_signature_from_another_key_is_rejected(
    verifier: CapabilityVerifier, clock: MovableClock
) -> None:
    attacker = SigningKey(kid="test-key-1", private_key=Ed25519PrivateKey.generate())
    token = mint(CapabilityMinter(attacker, clock=clock))
    assert verifier.verify(token, binding()).denial is CapabilityDenial.BAD_SIGNATURE


def test_unknown_key_id_is_rejected(verifier: CapabilityVerifier, clock: MovableClock) -> None:
    other = SigningKey(kid="rotated-away", private_key=Ed25519PrivateKey.generate())
    token = mint(CapabilityMinter(other, clock=clock))
    assert verifier.verify(token, binding()).denial is CapabilityDenial.UNKNOWN_KEY


def test_rotation_keeps_both_keys_verifiable(clock: MovableClock) -> None:
    """Old and new keys are trusted simultaneously so rotation needs no flag day. With a
    30-120s TTL the overlap window is tiny."""
    old = SigningKey(kid="old", private_key=Ed25519PrivateKey.generate())
    new = SigningKey(kid="new", private_key=Ed25519PrivateKey.generate())
    keyring = VerificationKeyring(keys={"old": old.public_key, "new": new.public_key})
    verifier = CapabilityVerifier(keyring, clock=clock)
    assert verifier.verify(mint(CapabilityMinter(old, clock=clock)), binding()).ok
    assert verifier.verify(mint(CapabilityMinter(new, clock=clock)), binding()).ok


@pytest.mark.parametrize(
    "token",
    ["", "notatoken", "a.b", "....", "!!!.???", "onlyonepart"],
)
def test_malformed_tokens_are_rejected(verifier: CapabilityVerifier, token: str) -> None:
    result = verifier.verify(token, binding())
    assert result.ok is False
    assert result.denial in {CapabilityDenial.MALFORMED, CapabilityDenial.UNKNOWN_KEY}


def test_scopeless_grant_is_refused(minter: CapabilityMinter) -> None:
    with pytest.raises(CapabilityError, match="grants nothing"):
        mint(minter, scopes=[])


# --------------------------------------------------------------------------- replay


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


async def test_a_grant_can_be_redeemed_once(
    session: AsyncSession, minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    result = verifier.verify(mint(minter), binding())
    assert result.claims is not None
    redeemer = CapabilityRedeemer(session)
    assert await redeemer.redeem(result.claims, operation_id="op-1") is True


async def test_replay_is_rejected_by_the_database_constraint(
    session: AsyncSession, minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    """The primary key does the enforcing. A SELECT-then-INSERT would let two concurrent
    gateway calls both observe "not yet redeemed" and both proceed."""
    result = verifier.verify(mint(minter), binding())
    assert result.claims is not None
    redeemer = CapabilityRedeemer(session)

    assert await redeemer.redeem(result.claims, operation_id="op-1") is True
    assert await redeemer.redeem(result.claims, operation_id="op-1") is False


async def test_replay_under_a_different_operation_is_also_rejected(
    session: AsyncSession, minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    """Moving a used grant onto a different operation is the interesting attack, not
    re-running the same one."""
    result = verifier.verify(mint(minter), binding())
    assert result.claims is not None
    redeemer = CapabilityRedeemer(session)

    assert await redeemer.redeem(result.claims, operation_id="op-1") is True
    assert await redeemer.redeem(result.claims, operation_id="op-2") is False


async def test_distinct_grants_redeem_independently(
    session: AsyncSession, minter: CapabilityMinter, verifier: CapabilityVerifier
) -> None:
    redeemer = CapabilityRedeemer(session)
    for index in range(3):
        result = verifier.verify(mint(minter), binding())
        assert result.claims is not None
        assert await redeemer.redeem(result.claims, operation_id=f"op-{index}") is True


# --------------------------------------------------------------------------- result type


def test_verification_result_cannot_be_incoherent() -> None:
    with pytest.raises(ValueError, match="cannot carry a denial"):
        VerificationResult(ok=True, denial=CapabilityDenial.EXPIRED)
    with pytest.raises(ValueError, match="must say why"):
        VerificationResult(ok=False)


def test_request_hash_covers_the_arguments() -> None:
    assert compute_request_hash({"a": 1}) != compute_request_hash({"a": 2})
    assert compute_request_hash({"a": 1, "b": 2}) == compute_request_hash({"b": 2, "a": 1})
