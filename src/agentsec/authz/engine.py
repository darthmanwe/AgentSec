"""Policy engine protocol and the fail-closed OPA client (AS-008).

Authorization lives outside the process that plans actions. That separation is only worth
anything if the failure modes are right, so this module has one overriding rule:

**Nothing that can go wrong here produces an ALLOW.**

Unreachable engine, timeout, HTTP error, malformed JSON, unknown outcome value, or an
outright bug in this file — every path returns a DENY marked ``fail_closed``. The public
method does not raise, because a caller catching an exception is a caller that might
decide to continue.

``fail_closed`` is retained as a distinct field rather than folded into the reason code, so
metrics can separate "policy said no" from "policy could not be reached". A spike in the
second is an outage, not an attack, and treating them alike would hide both.
"""

from __future__ import annotations

import datetime as dt
import time
from typing import Any, Final, Protocol, runtime_checkable

import httpx

from agentsec.authz.models import (
    AuthorizationRequest,
    ObligationKind,
    PolicyDecision,
    PolicyObligation,
    PolicyOutcome,
)
from agentsec.log import get_logger

log = get_logger("agentsec.authz.engine")

#: Default Rego entrypoint. The bundle (AS-009) exposes a single decision document so that
#: adding a rule cannot accidentally add a new way to be allowed.
DEFAULT_DECISION_PATH: Final = "agentsec/authz/decision"

#: Cap on the response body. An engine returning something enormous is malfunctioning, and
#: parsing it would turn a policy outage into a memory problem.
MAX_RESPONSE_BYTES: Final = 256 * 1024


class PolicyEngineError(Exception):
    """Internal signal. Never escapes :meth:`OpaPolicyClient.evaluate`."""


@runtime_checkable
class PolicyEngine(Protocol):
    """The authorization decision point.

    Implementations **must not raise**. A policy engine that throws forces every call site
    to decide what to do on failure, and some of them will get it wrong.
    """

    async def evaluate(self, request: AuthorizationRequest) -> PolicyDecision: ...


def _fail_closed(reason_code: str, latency_ms: float | None = None) -> PolicyDecision:
    return PolicyDecision(
        outcome=PolicyOutcome.DENY,
        reason_code=reason_code,
        fail_closed=True,
        evaluated_at=dt.datetime.now(dt.UTC),
        latency_ms=latency_ms,
    )


class DenyAllPolicyEngine:
    """An engine that denies everything.

    The safe default wherever an engine is required but none is configured. Present so
    that "no policy engine" is a working, denying configuration rather than a crash that
    somebody works around by skipping the check.
    """

    async def evaluate(self, request: AuthorizationRequest) -> PolicyDecision:
        return PolicyDecision(
            outcome=PolicyOutcome.DENY,
            reason_code="no_policy_engine_configured",
            fail_closed=True,
            evaluated_at=dt.datetime.now(dt.UTC),
        )


class OpaPolicyClient:
    """HTTP client for Open Policy Agent.

    OPA is pinned at 1.20.1, where Rego v1 syntax is mandatory (``if`` and ``contains``
    required on all rules) — see AS-009.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 2.0,
        decision_path: str = DEFAULT_DECISION_PATH,
        client: httpx.AsyncClient | None = None,
        policy_bundle_hash: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._decision_path = decision_path.strip("/")
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._policy_bundle_hash = policy_bundle_hash

    @property
    def decision_url(self) -> str:
        return f"{self._base_url}/v1/data/{self._decision_path}"

    async def aclose(self) -> None:
        if self._owned_client:
            await self._client.aclose()

    async def __aenter__(self) -> OpaPolicyClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def evaluate(self, request: AuthorizationRequest) -> PolicyDecision:
        """Ask OPA for a decision. Never raises; never returns ALLOW on error."""
        started = time.perf_counter()
        try:
            body = self._build_input(request)
            response = await self._client.post(
                self.decision_url,
                json={"input": body},
                timeout=self._timeout,
            )
            decision = self._parse(response, started)
        except httpx.TimeoutException:
            decision = self._deny("policy_engine_timeout", started)
        except httpx.HTTPError:
            decision = self._deny("policy_engine_unreachable", started)
        except PolicyEngineError as exc:
            decision = self._deny(str(exc), started)
        except Exception:
            # A bug in this module must still deny. Broad by design: the alternative is an
            # unhandled exception propagating into a caller that may treat it as "carry on".
            log.exception("policy evaluation failed unexpectedly")
            decision = self._deny("policy_engine_internal_error", started)

        log.info(
            "policy decision",
            outcome=decision.outcome.value,
            reason_code=decision.reason_code,
            fail_closed=decision.fail_closed,
            tool=request.intent.tool,
            operation=request.intent.operation,
            latency_ms=decision.latency_ms,
        )
        return decision

    # ------------------------------------------------------------------ internals

    def _deny(self, reason_code: str, started: float) -> PolicyDecision:
        return _fail_closed(reason_code, (time.perf_counter() - started) * 1000)

    def _build_input(self, request: AuthorizationRequest) -> dict[str, Any]:
        """Build the Rego input document.

        Deliberately complete and self-contained: a decision that depended on ambient
        state could not be replayed from the audit log. Note what is *absent* — no context
        text is passed, only a count. Putting attacker-controlled text inside the policy
        input would give it a route into the decision itself.
        """
        intent = request.intent
        return {
            "principal": {
                "id": request.principal.id,
                "kind": request.principal.kind.value,
                "workflow_id": request.principal.workflow_id,
            },
            "action": {
                "tool": intent.tool,
                "operation": intent.operation,
                "qualified_name": intent.qualified_name,
                "risk_class": intent.risk_class.value,
                "is_mutating": intent.is_mutating,
                "resource": {
                    "scheme": intent.resource.scheme,
                    "identifier": intent.resource.identifier,
                    "uri": intent.resource.uri,
                },
                "argument_keys": sorted(intent.arguments),
                "has_preconditions": intent.preconditions is not None
                and not intent.preconditions.is_empty,
            },
            "environment": request.environment,
            "registry_hash": request.registry_hash,
            "untrusted_context_count": request.untrusted_context_count,
        }

    def _parse(self, response: httpx.Response, started: float) -> PolicyDecision:
        latency_ms = (time.perf_counter() - started) * 1000

        if response.status_code != httpx.codes.OK:
            raise PolicyEngineError("policy_engine_http_error")

        if len(response.content) > MAX_RESPONSE_BYTES:
            raise PolicyEngineError("policy_engine_oversized_response")

        try:
            document = response.json()
        except ValueError as exc:
            raise PolicyEngineError("policy_engine_malformed_response") from exc

        if not isinstance(document, dict):
            raise PolicyEngineError("policy_engine_malformed_response")

        if "result" not in document:
            # OPA omits `result` when the queried path is undefined. Default-deny in the
            # bundle should make that impossible, but an undefined decision must never be
            # read as permission.
            raise PolicyEngineError("policy_decision_undefined")

        result = document["result"]
        if not isinstance(result, dict):
            raise PolicyEngineError("policy_engine_malformed_response")

        raw_outcome = result.get("outcome")
        if not isinstance(raw_outcome, str):
            # Covers null, numbers and booleans in one check: the outcome must be one of
            # three exact strings, and anything else is a malfunctioning engine.
            raise PolicyEngineError("policy_engine_unknown_outcome")
        try:
            outcome = PolicyOutcome(raw_outcome)
        except ValueError as exc:
            # An unrecognised outcome is not a reason to guess.
            raise PolicyEngineError("policy_engine_unknown_outcome") from exc

        reason_code = result.get("reason_code")
        if not isinstance(reason_code, str) or not reason_code:
            raise PolicyEngineError("policy_engine_missing_reason_code")

        return PolicyDecision(
            outcome=outcome,
            reason_code=reason_code,
            obligations=self._parse_obligations(result.get("obligations")),
            fail_closed=False,
            policy_bundle_hash=result.get("policy_bundle_hash") or self._policy_bundle_hash,
            evaluated_at=dt.datetime.now(dt.UTC),
            latency_ms=latency_ms,
        )

    @staticmethod
    def _parse_obligations(raw: Any) -> tuple[PolicyObligation, ...]:
        """Parse obligations, dropping ones this build does not recognise.

        Unknown obligations are ignored rather than fatal, but only because an obligation
        can never *widen* a decision — it constrains an outcome that has already been
        granted. An unknown *outcome*, by contrast, is fatal.
        """
        if raw is None:
            return ()
        if not isinstance(raw, list):
            raise PolicyEngineError("policy_engine_malformed_obligations")

        parsed: list[PolicyObligation] = []
        for item in raw:
            if not isinstance(item, dict):
                raise PolicyEngineError("policy_engine_malformed_obligations")
            raw_kind = item.get("kind")
            if not isinstance(raw_kind, str):
                raise PolicyEngineError("policy_engine_malformed_obligations")
            try:
                kind = ObligationKind(raw_kind)
            except ValueError:
                log.warning("ignoring unknown policy obligation", kind=raw_kind)
                continue
            parsed.append(PolicyObligation(kind=kind, value=item.get("value")))
        return tuple(parsed)


__all__ = [
    "DEFAULT_DECISION_PATH",
    "MAX_RESPONSE_BYTES",
    "DenyAllPolicyEngine",
    "OpaPolicyClient",
    "PolicyEngine",
    "PolicyEngineError",
]
