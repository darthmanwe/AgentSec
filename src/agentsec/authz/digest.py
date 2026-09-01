"""Canonical action normalisation and digest (AS-007).

A cryptographic identity for one exact proposed action. Approvals, capability grants and
the execution ledger are all bound to this digest, so every ambiguity in the encoding is
an approval-bypass vector, not a formatting preference.

The full specification, with rationale for each rule, is in
``docs/CANONICAL_ACTION_DIGEST.md``. Golden fixtures in ``tests/data/digest_golden.json``
pin the algorithm so an accidental change fails a test rather than silently invalidating
every stored approval.

The single most important property of this module is not the hash. It is that
:func:`canonicalize` returns the **canonical bytes that must actually be dispatched**.
Hashing a normalised form and then sending the caller's original input is a signature
bypass: what was approved and what executes would differ. Callers take
``CanonicalAction.arguments``, never their own dict.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any, Final

from agentsec.authz.models import ActionIntent, Principal

#: Domain separation. Prefixed to the hash input so a digest produced under this scheme
#: can never collide with one produced under a different scheme, and so the algorithm can
#: version without a v2 digest silently matching a v1 approval.
DIGEST_DOMAIN: Final = "agentsec.action.v1"

#: Bound on argument nesting. Unbounded recursion in a function that runs on
#: attacker-influenced input is a denial-of-service waiting to happen.
MAX_DEPTH: Final = 16


class CanonicalisationError(ValueError):
    """Raised when a value cannot be represented canonically.

    Always a hard failure. Falling back to a lossy encoding would mean two different
    actions could share a digest, which is the one thing this module exists to prevent.
    """


def _normalise_string(value: str) -> str:
    """NFC-normalise. Two strings that render identically must hash identically.

    Without this, ``café`` composed (U+00E9) and decomposed (e + U+0301) are different
    byte sequences, so an approval for one would not cover the other despite them being
    indistinguishable to the human who approved it.
    """
    return unicodedata.normalize("NFC", value)


def _canonicalise_value(value: Any, path: str = "$", depth: int = 0) -> Any:
    """Recursively convert a value to its canonical representation."""
    if depth > MAX_DEPTH:
        raise CanonicalisationError(f"{path}: nesting exceeds {MAX_DEPTH} levels")

    if value is None:
        # Preserved, and distinct from an absent key. {"x": null} and {} are different
        # actions: one explicitly passes a null argument, the other omits it entirely.
        return None

    if isinstance(value, bool):
        # Checked before int: bool subclasses int and would otherwise become 1/0.
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        raise CanonicalisationError(
            f"{path}: floats cannot be canonicalised because they do not round-trip "
            "exactly; pass a decimal string instead"
        )

    if isinstance(value, str):
        return _normalise_string(value)

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise CanonicalisationError(
                    f"{path}: object keys must be strings, got {type(raw_key).__name__}"
                )
            key = _normalise_string(raw_key)
            if key in out:
                # Two distinct keys that normalise to the same string would make the
                # encoding depend on dict iteration order.
                raise CanonicalisationError(
                    f"{path}: duplicate key after Unicode normalisation: {key!r}"
                )
            out[key] = _canonicalise_value(item, f"{path}.{key}", depth + 1)
        return out

    if isinstance(value, list):
        # Order is significant and preserved. ["a","b"] and ["b","a"] are different
        # actions: for an argument like a file list, the order can change behaviour.
        return [
            _canonicalise_value(item, f"{path}[{i}]", depth + 1) for i, item in enumerate(value)
        ]

    if isinstance(value, tuple):
        return [
            _canonicalise_value(item, f"{path}[{i}]", depth + 1) for i, item in enumerate(value)
        ]

    raise CanonicalisationError(
        f"{path}: {type(value).__name__} has no canonical representation; "
        "actions may contain only null, bool, int, str, list and object"
    )


def canonical_json(payload: dict[str, Any]) -> bytes:
    """Serialise a canonical payload to deterministic UTF-8 bytes.

    ``sort_keys`` orders by Unicode code point, separators carry no whitespace, and
    ``ensure_ascii=False`` keeps text as UTF-8 rather than escaping it — one encoding of
    a given document, on every platform and Python version.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class CanonicalAction:
    """An action reduced to its canonical form, with its identity.

    ``arguments`` is what callers must dispatch. Using the original input instead would
    mean the approved bytes and the executed bytes differ.
    """

    digest: str
    payload: dict[str, Any]
    canonical_bytes: bytes

    @property
    def arguments(self) -> dict[str, Any]:
        """The canonicalised arguments. **Dispatch these, not the caller's dict.**"""
        args: dict[str, Any] = self.payload["arguments"]
        return args

    @property
    def qualified_name(self) -> str:
        return f"{self.payload['tool']}.{self.payload['operation']}"


def build_payload(
    principal: Principal,
    intent: ActionIntent,
    *,
    workflow_id: str | None = None,
) -> dict[str, Any]:
    """Assemble the document that gets hashed.

    Timestamps are deliberately excluded: the same action proposed twice is the same
    action, and including a clock reading would make every digest unique and every
    approval unmatchable.

    ``run_id`` is excluded for the same reason — it identifies an execution, not an
    action. ``workflow_id`` *is* included, so an approval granted in one workflow cannot
    be replayed into another.
    """
    preconditions = (
        None
        if intent.preconditions is None or intent.preconditions.is_empty
        else {
            "commit_sha": intent.preconditions.commit_sha,
            "pr_head_sha": intent.preconditions.pr_head_sha,
            "resource_version": intent.preconditions.resource_version,
        }
    )

    payload: dict[str, Any] = {
        "domain": DIGEST_DOMAIN,
        "principal": {
            "id": principal.id,
            "kind": principal.kind.value,
        },
        "workflow_id": workflow_id if workflow_id is not None else principal.workflow_id,
        "tool": intent.tool,
        "operation": intent.operation,
        "resource": {
            "scheme": intent.resource.scheme,
            "identifier": intent.resource.identifier,
        },
        # risk_class comes from the trusted registry, so a registry change that
        # reclassifies an action correctly invalidates approvals granted under the old
        # classification.
        "risk_class": intent.risk_class.value,
        "arguments": intent.arguments,
        "preconditions": preconditions,
    }
    return _canonicalise_value(payload)  # type: ignore[no-any-return]


def canonicalize(
    principal: Principal,
    intent: ActionIntent,
    *,
    workflow_id: str | None = None,
) -> CanonicalAction:
    """Reduce an action to canonical form and compute its digest."""
    payload = build_payload(principal, intent, workflow_id=workflow_id)
    body = canonical_json(payload)

    # The domain string is inside the payload *and* prefixed to the hash input. The
    # payload copy makes the canonical form self-describing when read in an audit log;
    # the prefix guarantees domain separation even if a future payload shape drops it.
    material = DIGEST_DOMAIN.encode("utf-8") + b"\n" + body
    return CanonicalAction(
        digest=hashlib.sha256(material).hexdigest(),
        payload=payload,
        canonical_bytes=material,
    )


def compute_digest(
    principal: Principal,
    intent: ActionIntent,
    *,
    workflow_id: str | None = None,
) -> str:
    """Digest only, for call sites that do not dispatch."""
    return canonicalize(principal, intent, workflow_id=workflow_id).digest


def digests_match(left: str, right: str) -> bool:
    """Constant-time digest comparison.

    Digests are not secrets, so this is defence in depth rather than a strict necessity.
    It costs nothing and removes the need to reason about whether a timing side channel
    on approval matching is exploitable.
    """
    import hmac

    return hmac.compare_digest(left, right)


__all__ = [
    "DIGEST_DOMAIN",
    "MAX_DEPTH",
    "CanonicalAction",
    "CanonicalisationError",
    "build_payload",
    "canonical_json",
    "canonicalize",
    "compute_digest",
    "digests_match",
]
