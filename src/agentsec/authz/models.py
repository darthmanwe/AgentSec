"""Authorization domain contracts (AS-006).

These types are defined before any policy logic, because the shape of the request is what
the whole kernel agrees on. Three rules govern them:

**No untyped escape hatch in a critical field.** ``arguments`` is ``dict[str, JsonValue]``,
not ``dict[str, Any]``. An ``Any`` here would let an arbitrary Python object into the value
that gets hashed for the action digest, and a digest over something with an unstable
``repr`` is not an identity.

**Floats are rejected at the boundary.** The canonical digest (AS-007) cannot include
floats — ``0.1 + 0.2`` does not round-trip, so an approval could be bound to a value that
re-serialises differently. Rejecting them here rather than at hashing time means an
unhashable action cannot be constructed at all.

**Resources are normalised on construction.** A resource that normalises one way when
approved and another way when executed is an approval bypass. Normalisation belongs to the
type, not to whoever remembers to call a helper.

Also defines the provenance schema (``TrustLevel``, ``ContextItem``), which AS-025 was
originally going to introduce. The gateway needs trust labels at M2, long before agent
state exists at M4; defining it twice would produce two shapes to reconcile.
"""

from __future__ import annotations

import datetime as dt
import enum
import hashlib
import re
import unicodedata
from typing import Annotated, Any, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

# --------------------------------------------------------------------------- enums


class PrincipalKind(enum.StrEnum):
    AGENT = "agent"
    """The planner. Proposes; never authorises."""

    OPERATOR = "operator"
    """A human. The only kind that can approve."""

    SYSTEM = "system"
    """Internal machinery: workflow engine, scheduled maintenance."""


class RiskClass(enum.StrEnum):
    """How much damage an action could do, independent of who proposed it."""

    READ_ONLY = "read_only"
    LOW_RISK_WRITE = "low_risk_write"
    HIGH_RISK_WRITE = "high_risk_write"
    IRREVERSIBLE = "irreversible"
    # Suppression below: this is a risk-class label, not a credential. Bandit's S105
    # matches on the member name containing "SECRET".
    SECRET_ACCESS = "secret_access"  # noqa: S105
    """Always denied by policy. Present as a class so the attempt is classifiable and
    countable, not so it can ever be permitted."""


class PolicyOutcome(enum.StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class TrustLevel(enum.StrEnum):
    """Provenance of context. Nothing acquires authority by asserting it has authority."""

    TRUSTED = "trusted"
    """Version-controlled and hashed: the tool registry, the policy bundle."""

    UNTRUSTED = "untrusted"
    """Anything an attacker could have written: repository text, Jira text, scanner output,
    cloud tags, tool responses, MCP server self-description."""

    MODEL_GENERATED = "model_generated"
    """Model output. A structured input to be validated, never an instruction."""


class ObligationKind(enum.StrEnum):
    """What a policy requires *in addition* to its outcome."""

    REQUIRE_APPROVAL = "require_approval"
    CAPABILITY_TTL_SECONDS = "capability_ttl_seconds"
    REDACT_FIELDS = "redact_fields"
    MAX_RESULT_BYTES = "max_result_bytes"
    AUDIT_LEVEL = "audit_level"


# --------------------------------------------------------------------------- base


class Frozen(BaseModel):
    """Immutable, strict, no unexpected fields.

    ``extra="forbid"`` matters more than it looks: an authorization request carrying an
    unrecognised field is either a version mismatch or an injection attempt, and silently
    dropping it would hide both.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=False,
        validate_assignment=True,
        use_enum_values=False,
    )


# --------------------------------------------------------------------------- resource

_TRAVERSAL = re.compile(r"(^|[/\\])\.\.([/\\]|$)")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class ResourceRef(Frozen):
    """A normalised reference to something an action operates on.

    Normalisation is not cosmetic. If ``fixture://repo-a/src/./main.py`` and
    ``fixture://repo-a/src/main.py`` produce different digests, an approval for one does
    not cover the other — and an attacker who can influence the path spelling can request
    approval for a benign-looking form and execute a different one.
    """

    scheme: Annotated[str, Field(min_length=1, max_length=32)]
    identifier: Annotated[str, Field(min_length=1, max_length=512)]

    @field_validator("scheme", mode="before")
    @classmethod
    def _normalise_scheme(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        normalised = unicodedata.normalize("NFC", value).strip().lower()
        if not _SCHEME.match(normalised):
            raise ValueError(
                f"invalid resource scheme {value!r}: expected lowercase alphanumeric, "
                "optionally with + . or -"
            )
        return normalised

    @field_validator("identifier", mode="before")
    @classmethod
    def _normalise_identifier(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value

        # NFC first: two visually identical strings must not hash differently.
        normalised = unicodedata.normalize("NFC", value).strip()

        if _CONTROL_CHARS.search(normalised):
            raise ValueError("resource identifier contains control characters")

        # Backslashes are normalised to forward slashes before the traversal check, so a
        # Windows-style path cannot smuggle `..\` past a check that only looks for `../`.
        normalised = normalised.replace("\\", "/")
        normalised = re.sub(r"/{2,}", "/", normalised)
        normalised = re.sub(r"(^|/)\./", r"\1", normalised)
        normalised = normalised.rstrip("/") or "/"

        if _TRAVERSAL.search(normalised):
            raise ValueError(f"resource identifier contains path traversal: {value!r}")

        return normalised

    @property
    def uri(self) -> str:
        return f"{self.scheme}://{self.identifier}"

    def __str__(self) -> str:
        return self.uri


# --------------------------------------------------------------------------- principal


class Principal(Frozen):
    """Who is proposing or approving. Kind is structural, not advisory."""

    id: Annotated[str, Field(min_length=1, max_length=255)]
    kind: PrincipalKind
    run_id: Annotated[str | None, Field(max_length=64)] = None
    workflow_id: Annotated[str | None, Field(max_length=255)] = None

    @property
    def may_approve(self) -> bool:
        """Only a human operator can approve.

        Expressed as a property on the type so that no call site has to remember the rule,
        and so a test can assert it directly rather than inferring it from policy.
        """
        return self.kind is PrincipalKind.OPERATOR


# --------------------------------------------------------------------------- action


class Preconditions(Frozen):
    """Immutable world state the action was authorised against.

    Without these, a digest pins the *request* but not the *world*: a PR head can move
    between approval and execution, and the approved comment lands on different code.
    Part of the digest, so a changed precondition is a different action.
    """

    commit_sha: Annotated[str | None, Field(pattern=r"^[0-9a-f]{7,64}$")] = None
    pr_head_sha: Annotated[str | None, Field(pattern=r"^[0-9a-f]{7,64}$")] = None
    resource_version: Annotated[str | None, Field(max_length=255)] = None
    """ETag or equivalent, for backends that expose one."""

    @property
    def is_empty(self) -> bool:
        return not any((self.commit_sha, self.pr_head_sha, self.resource_version))


def _reject_floats(value: JsonValue, path: str = "arguments") -> None:
    """Recursively reject floats anywhere in an argument tree.

    ``bool`` is a subclass of ``int`` and is fine; ``float`` is not, because it does not
    round-trip through JSON reliably and the digest must be reproducible byte for byte.
    Callers wanting a decimal quantity pass a string.
    """
    if isinstance(value, float):
        raise ValueError(
            f"{path}: floats are not permitted in action arguments because the canonical "
            "digest must round-trip exactly; pass a decimal string instead"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")


class ActionIntent(Frozen):
    """A proposed action. Never, by itself, permission to perform it."""

    tool: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.]*$")]
    operation: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$")]
    resource: ResourceRef
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    preconditions: Preconditions | None = None
    risk_class: RiskClass

    @field_validator("arguments")
    @classmethod
    def _no_floats(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _reject_floats(value)
        return value

    @property
    def qualified_name(self) -> str:
        return f"{self.tool}.{self.operation}"

    @property
    def is_mutating(self) -> bool:
        return self.risk_class is not RiskClass.READ_ONLY


# --------------------------------------------------------------------------- context


class ContextItem(Frozen):
    """A piece of context with its provenance attached.

    Provenance is mandatory. There is no constructor that produces context of unknown
    origin, because "we lost track of where this came from" is how untrusted text ends up
    being treated as an instruction.
    """

    id: Annotated[str, Field(min_length=1, max_length=128)]
    source: Annotated[str, Field(min_length=1, max_length=255)]
    """Where it came from, concretely: ``fixture://repo-a/README.md``, ``jira:PROJ-14``."""

    trust: TrustLevel
    content: str
    retrieved_at: dt.datetime

    @field_validator("retrieved_at")
    @classmethod
    def _must_be_aware(cls, value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None:
            raise ValueError("retrieved_at must be timezone-aware")
        return value

    @property
    def content_hash(self) -> str:
        """Identity of the exact bytes seen, so evidence can be pinned to an approval."""
        return hashlib.sha256(
            unicodedata.normalize("NFC", self.content).encode("utf-8")
        ).hexdigest()

    @property
    def is_untrusted(self) -> bool:
        return self.trust is not TrustLevel.TRUSTED


# --------------------------------------------------------------------------- decisions


class PolicyObligation(Frozen):
    """A condition the policy attaches to its outcome."""

    kind: ObligationKind
    value: JsonValue = None


class AuthorizationRequest(Frozen):
    """Everything the policy engine is given. Deliberately complete and self-contained:
    a decision that depended on ambient state could not be replayed from the audit log."""

    principal: Principal
    intent: ActionIntent
    requested_at: dt.datetime

    registry_hash: Annotated[str | None, Field(pattern=r"^[0-9a-f]{64}$")] = None
    policy_bundle_hash: Annotated[str | None, Field(pattern=r"^[0-9a-f]{64}$")] = None
    environment: Annotated[str, Field(max_length=64)] = "local"

    untrusted_context_count: Annotated[int, Field(ge=0)] = 0
    """How many untrusted items informed the plan. Available to policy so it can be
    stricter when a plan was formed under heavy untrusted influence - but never the
    content itself, which would put attacker text inside the decision."""

    @field_validator("requested_at")
    @classmethod
    def _must_be_aware(cls, value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None:
            raise ValueError("requested_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _agents_cannot_request_as_operator(self) -> Self:
        """Structural expression of the core invariant: the model cannot present itself as
        the human who approves."""
        if self.principal.kind is PrincipalKind.OPERATOR and self.intent.is_mutating:
            # An operator-principal request is only meaningful for approval flows, which
            # do not route through here. Catching it at the type keeps the policy simpler.
            raise ValueError(
                "operator principals do not submit mutating authorization requests; "
                "approvals are recorded through the approval service"
            )
        return self


class PolicyDecision(Frozen):
    """The engine's answer. Fail-closed is a first-class field, not an inference."""

    outcome: PolicyOutcome
    reason_code: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$")]
    obligations: tuple[PolicyObligation, ...] = ()
    fail_closed: bool = False
    """True when this DENY came from the engine being unreachable, timing out, or
    returning something unparseable - rather than from a rule. A spike in these is an
    outage, not an attack, and the two must stay distinguishable in the metrics."""

    policy_bundle_hash: Annotated[str | None, Field(pattern=r"^[0-9a-f]{64}$")] = None
    evaluated_at: dt.datetime | None = None
    latency_ms: Annotated[float | None, Field(ge=0)] = None

    @model_validator(mode="after")
    def _fail_closed_implies_deny(self) -> Self:
        if self.fail_closed and self.outcome is not PolicyOutcome.DENY:
            raise ValueError("fail_closed decisions must be DENY")
        return self

    @property
    def permits_execution(self) -> bool:
        """Only ALLOW permits execution.

        REQUIRE_APPROVAL explicitly does not: it is a request for authority, not a grant
        of it. Writing this as a property rather than leaving each call site to compare
        against an enum removes the opportunity to get it backwards.
        """
        return self.outcome is PolicyOutcome.ALLOW

    def obligation(self, kind: ObligationKind) -> JsonValue | None:
        for item in self.obligations:
            if item.kind is kind:
                return item.value
        return None


DENY_UNAVAILABLE = PolicyDecision(
    outcome=PolicyOutcome.DENY,
    reason_code="policy_engine_unavailable",
    fail_closed=True,
)
"""The canonical fail-closed decision, so every error path returns the identical value
rather than each constructing its own near-miss."""


__all__ = [
    "DENY_UNAVAILABLE",
    "ActionIntent",
    "AuthorizationRequest",
    "ContextItem",
    "Frozen",
    "ObligationKind",
    "PolicyDecision",
    "PolicyObligation",
    "PolicyOutcome",
    "Preconditions",
    "Principal",
    "PrincipalKind",
    "ResourceRef",
    "RiskClass",
    "TrustLevel",
]
