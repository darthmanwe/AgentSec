"""Short-lived scoped capability grants (AS-011).

A capability is authority to perform **one action, once, within about a minute**. It is
minted only after policy allows (and, for mutations, after an operator approves the exact
digest), and it is bound so tightly that it is useless anywhere else:

    subject · audience · environment · workflow · action digest · request hash
    · tool · resource · scopes · expiry · jti · kid · registry hash · policy hash

Every one of those is verified. A grant that is valid for the Jira issue you approved is
not valid for a different issue, a different tool, a different workflow, a different
environment, or the same action with one argument changed — because changing an argument
changes the action digest (AS-007).

**Single use, and why that does not break retries.** Redemption is recorded in
``capability_jti_uses``, whose primary key does the enforcing: a second redemption of the
same ``jti`` violates the constraint and the database rejects it, rather than relying on a
read-then-write that two concurrent gateway calls could both pass.

That would deadlock against Temporal retries on its own — a retry whose response was lost
would present a consumed ``jti`` and be denied, leaving the workflow unable to finish. It
does not, because the **execution ledger (AS-022) is consulted first**: a retry whose
logical operation already completed returns the cached result and never reaches redemption.
The ordering is the whole design, and it is what ADR-0001 records.
"""

from __future__ import annotations

import base64
import datetime as dt
import enum
import hashlib
import hmac
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agentsec.authz.digest import canonical_json
from agentsec.authz.keys import SigningKey, VerificationKeyring
from agentsec.db.models import CapabilityJtiUse
from agentsec.log import get_logger

log = get_logger("agentsec.authz.capabilities")

CAPABILITY_DOMAIN: Final = "agentsec.capability.v1"

#: Bounds from the AS-011 specification. Authority that outlives reasoning about it is not
#: authority that can be audited.
MIN_TTL_SECONDS: Final = 30
MAX_TTL_SECONDS: Final = 120

#: Tolerance for clock skew between the minting service and the verifying gateway. Kept
#: deliberately small: a generous window here extends the life of every grant.
CLOCK_SKEW_SECONDS: Final = 5

Clock = Callable[[], dt.datetime]


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class CapabilityDenial(enum.StrEnum):
    """Why a capability was refused.

    Granular on purpose. "The token was rejected" is not an audit trail; these values are
    what let a report distinguish an expired grant from a replayed one from an attempt to
    aim a valid grant at a different resource.
    """

    MALFORMED = "capability_malformed"
    UNKNOWN_KEY = "capability_unknown_key_id"
    BAD_SIGNATURE = "capability_bad_signature"
    EXPIRED = "capability_expired"
    NOT_YET_VALID = "capability_not_yet_valid"
    TTL_OUT_OF_BOUNDS = "capability_ttl_out_of_bounds"
    WRONG_AUDIENCE = "capability_wrong_audience"
    WRONG_ENVIRONMENT = "capability_wrong_environment"
    WRONG_SUBJECT = "capability_wrong_subject"
    WRONG_WORKFLOW = "capability_wrong_workflow"
    WRONG_DIGEST = "capability_wrong_action_digest"
    WRONG_REQUEST = "capability_wrong_request_hash"
    WRONG_TOOL = "capability_wrong_tool"
    WRONG_RESOURCE = "capability_wrong_resource"
    MISSING_SCOPE = "capability_missing_scope"
    STALE_REGISTRY = "capability_stale_registry"
    STALE_POLICY = "capability_stale_policy"
    REPLAYED = "capability_replayed"


class CapabilityError(Exception):
    """Raised for minting misuse. Verification failures are values, not exceptions."""


@dataclass(frozen=True, slots=True)
class CapabilityClaims:
    """The signed payload. Every field is verified; none is decorative."""

    jti: str
    subject: str
    audience: str
    environment: str
    workflow_id: str
    action_digest: str
    request_hash: str
    tool: str
    resource: str
    scopes: tuple[str, ...]
    key_id: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    registry_hash: str | None = None
    policy_bundle_hash: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "domain": CAPABILITY_DOMAIN,
            "jti": self.jti,
            "sub": self.subject,
            "aud": self.audience,
            "env": self.environment,
            "wf": self.workflow_id,
            "action_digest": self.action_digest,
            "request_hash": self.request_hash,
            "tool": self.tool,
            "resource": self.resource,
            "scopes": sorted(self.scopes),
            "kid": self.key_id,
            "iat": self.issued_at.isoformat(),
            "exp": self.expires_at.isoformat(),
            "registry_hash": self.registry_hash,
            "policy_bundle_hash": self.policy_bundle_hash,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> CapabilityClaims:
        if payload.get("domain") != CAPABILITY_DOMAIN:
            raise ValueError("wrong capability domain")
        return cls(
            jti=str(payload["jti"]),
            subject=str(payload["sub"]),
            audience=str(payload["aud"]),
            environment=str(payload["env"]),
            workflow_id=str(payload["wf"]),
            action_digest=str(payload["action_digest"]),
            request_hash=str(payload["request_hash"]),
            tool=str(payload["tool"]),
            resource=str(payload["resource"]),
            scopes=tuple(payload["scopes"]),
            key_id=str(payload["kid"]),
            issued_at=dt.datetime.fromisoformat(payload["iat"]),
            expires_at=dt.datetime.fromisoformat(payload["exp"]),
            registry_hash=payload.get("registry_hash"),
            policy_bundle_hash=payload.get("policy_bundle_hash"),
        )

    @property
    def ttl_seconds(self) -> float:
        return (self.expires_at - self.issued_at).total_seconds()


@dataclass(frozen=True, slots=True)
class ExpectedBinding:
    """What the verifier requires the grant to be bound to.

    Supplied by the gateway from the *request it is about to dispatch*, never read out of
    the token. A verifier that took its expectations from the thing it is verifying would
    check nothing at all.
    """

    subject: str
    audience: str
    environment: str
    workflow_id: str
    action_digest: str
    request_hash: str
    tool: str
    resource: str
    required_scopes: Sequence[str] = ()
    registry_hash: str | None = None
    policy_bundle_hash: str | None = None


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    denial: CapabilityDenial | None = None
    claims: CapabilityClaims | None = None

    def __post_init__(self) -> None:
        if self.ok and self.denial is not None:
            raise ValueError("a successful verification cannot carry a denial")
        if not self.ok and self.denial is None:
            raise ValueError("a failed verification must say why")


def compute_request_hash(arguments: dict[str, Any]) -> str:
    """Bind a grant to one exact request body.

    Uses the canonicalised arguments (AS-007), so this hash covers what will actually be
    dispatched. Without it, a valid grant could be moved onto a different call to the same
    tool and resource.
    """
    return hashlib.sha256(b"agentsec.request.v1\n" + canonical_json(arguments)).hexdigest()


class CapabilityMinter:
    """Mints capability grants. **Must be unreachable from the planner.**

    ``tests/test_import_boundaries.py`` asserts structurally that nothing under
    ``agentsec.agent`` can import this module. That is the mechanical form of the core
    invariant: the model may request a capability, never mint one.
    """

    def __init__(self, signing_key: SigningKey, *, clock: Clock = _utc_now) -> None:
        self._key = signing_key
        self._clock = clock

    def mint(
        self,
        *,
        subject: str,
        audience: str,
        environment: str,
        workflow_id: str,
        action_digest: str,
        request_hash: str,
        tool: str,
        resource: str,
        scopes: Sequence[str],
        ttl_seconds: int,
        approval_expires_at: dt.datetime | None = None,
        registry_hash: str | None = None,
        policy_bundle_hash: str | None = None,
    ) -> str:
        """Mint a signed grant and return its token.

        The expiry is ``min(now + ttl, approval_expiry)``. A grant must never outlive the
        approval that authorised it, or a slow execution could act on authority the
        operator had already let lapse.
        """
        if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
            raise CapabilityError(
                f"ttl {ttl_seconds}s outside the permitted "
                f"{MIN_TTL_SECONDS}-{MAX_TTL_SECONDS}s window"
            )
        if not scopes:
            raise CapabilityError("a capability with no scopes grants nothing; refusing to mint")

        issued_at = self._clock()
        expires_at = issued_at + dt.timedelta(seconds=ttl_seconds)
        if approval_expires_at is not None:
            expires_at = min(expires_at, approval_expires_at)
            if expires_at <= issued_at:
                raise CapabilityError(
                    "approval expires at or before now; refusing to mint a dead grant"
                )

        claims = CapabilityClaims(
            jti=f"cap-{uuid.uuid4().hex}",
            subject=subject,
            audience=audience,
            environment=environment,
            workflow_id=workflow_id,
            action_digest=action_digest,
            request_hash=request_hash,
            tool=tool,
            resource=resource,
            scopes=tuple(sorted(scopes)),
            key_id=self._key.kid,
            issued_at=issued_at,
            expires_at=expires_at,
            registry_hash=registry_hash,
            policy_bundle_hash=policy_bundle_hash,
        )

        body = canonical_json(claims.to_payload())
        signature = self._key.private_key.sign(body)
        log.info(
            "capability minted",
            jti=claims.jti,
            tool=tool,
            action_digest=action_digest,
            expires_at=expires_at.isoformat(),
        )
        return f"{_b64(body)}.{_b64(signature)}"


class CapabilityVerifier:
    """Verifies grants. Pure: no database, no network, no clock beyond the injected one."""

    def __init__(self, keyring: VerificationKeyring, *, clock: Clock = _utc_now) -> None:
        self._keyring = keyring
        self._clock = clock

    def verify(self, token: str, expected: ExpectedBinding) -> VerificationResult:
        """Check every binding. Returns a result; never raises on a bad token."""
        try:
            body_b64, signature_b64 = token.split(".", 1)
            body = _unb64(body_b64)
            signature = _unb64(signature_b64)
            import json

            claims = CapabilityClaims.from_payload(json.loads(body))
        except Exception:
            return VerificationResult(ok=False, denial=CapabilityDenial.MALFORMED)

        public_key = self._keyring.get(claims.key_id)
        if public_key is None:
            return VerificationResult(ok=False, denial=CapabilityDenial.UNKNOWN_KEY)

        try:
            public_key.verify(signature, body)
        except InvalidSignature:
            return VerificationResult(ok=False, denial=CapabilityDenial.BAD_SIGNATURE, claims=None)

        # Signature is good from here on, so the claims can be trusted as *authentic* -
        # which is not the same as applicable. Everything below checks applicability.
        now = self._clock()

        if claims.ttl_seconds > MAX_TTL_SECONDS + CLOCK_SKEW_SECONDS:
            # A correctly signed grant with an absurd lifetime means the minter was
            # misconfigured or compromised; the verifier does not have to honour it.
            return self._deny(CapabilityDenial.TTL_OUT_OF_BOUNDS, claims)

        if now >= claims.expires_at:
            return self._deny(CapabilityDenial.EXPIRED, claims)

        if now < claims.issued_at - dt.timedelta(seconds=CLOCK_SKEW_SECONDS):
            return self._deny(CapabilityDenial.NOT_YET_VALID, claims)

        checks: list[tuple[bool, CapabilityDenial]] = [
            (_eq(claims.subject, expected.subject), CapabilityDenial.WRONG_SUBJECT),
            (_eq(claims.audience, expected.audience), CapabilityDenial.WRONG_AUDIENCE),
            (_eq(claims.environment, expected.environment), CapabilityDenial.WRONG_ENVIRONMENT),
            (_eq(claims.workflow_id, expected.workflow_id), CapabilityDenial.WRONG_WORKFLOW),
            (_eq(claims.action_digest, expected.action_digest), CapabilityDenial.WRONG_DIGEST),
            (_eq(claims.request_hash, expected.request_hash), CapabilityDenial.WRONG_REQUEST),
            (_eq(claims.tool, expected.tool), CapabilityDenial.WRONG_TOOL),
            (_eq(claims.resource, expected.resource), CapabilityDenial.WRONG_RESOURCE),
        ]
        for passed, denial in checks:
            if not passed:
                return self._deny(denial, claims)

        if not set(expected.required_scopes).issubset(claims.scopes):
            return self._deny(CapabilityDenial.MISSING_SCOPE, claims)

        if expected.registry_hash is not None and not _eq(
            claims.registry_hash or "", expected.registry_hash
        ):
            # The tool registry changed after minting. Risk classifications may have moved,
            # so the authorization that produced this grant no longer describes reality.
            return self._deny(CapabilityDenial.STALE_REGISTRY, claims)

        if expected.policy_bundle_hash is not None and not _eq(
            claims.policy_bundle_hash or "", expected.policy_bundle_hash
        ):
            return self._deny(CapabilityDenial.STALE_POLICY, claims)

        return VerificationResult(ok=True, claims=claims)

    @staticmethod
    def _deny(denial: CapabilityDenial, claims: CapabilityClaims) -> VerificationResult:
        log.warning("capability rejected", denial=denial.value, jti=claims.jti, tool=claims.tool)
        return VerificationResult(ok=False, denial=denial, claims=claims)


def _eq(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


class CapabilityRedeemer:
    """Records single use of a grant.

    The database constraint does the enforcing. A ``SELECT`` then ``INSERT`` would let two
    concurrent gateway calls both observe "not yet redeemed" and both proceed; an insert
    that violates the primary key cannot.

    Callers must consult the execution ledger (AS-022) **before** redeeming, or a Temporal
    retry will present a consumed ``jti`` and deadlock the workflow.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def redeem(self, claims: CapabilityClaims, *, operation_id: str) -> bool:
        """Consume the grant. Returns False if it was already used.

        The insert runs inside a **savepoint**. A plain ``session.rollback()`` on the
        constraint violation would discard every other uncommitted change in the same
        session - in practice the execution ledger entry written moments earlier by
        AS-022, silently erasing the record of a completed side effect while reporting
        only that a replay was rejected. Found by the AS-022 tests, which counted logical
        effects and got zero.

        Scoping the rollback to this statement keeps the failure local, which is the only
        thing it should affect.
        """
        try:
            async with self._session.begin_nested():
                self._session.add(
                    CapabilityJtiUse(
                        jti=claims.jti,
                        operation_id=operation_id,
                        request_hash=claims.request_hash,
                    )
                )
                await self._session.flush()
        except IntegrityError:
            log.warning("capability replay rejected", jti=claims.jti, operation_id=operation_id)
            return False
        return True


__all__ = [
    "CAPABILITY_DOMAIN",
    "CLOCK_SKEW_SECONDS",
    "MAX_TTL_SECONDS",
    "MIN_TTL_SECONDS",
    "CapabilityClaims",
    "CapabilityDenial",
    "CapabilityError",
    "CapabilityMinter",
    "CapabilityRedeemer",
    "CapabilityVerifier",
    "ExpectedBinding",
    "VerificationResult",
    "compute_request_hash",
]
