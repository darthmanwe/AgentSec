"""What the structured-output API will actually accept (AS-040).

This module exists because a rehearsal on a mock cannot catch a schema the real API
refuses. The first live smoke run of the funded evaluation failed all 22 calls with::

    400 invalid_request_error
    output_config.format.schema: For 'array' type, property 'maxItems' is not supported

Every call. The dry run had passed, because ``MockProvider`` accepts any schema handed to
it — so the rehearsal validated the pipeline and silently skipped the one thing that would
have stopped the funded sweep. Had the ceiling been $18 rather than $1, the run would have
burned all 660 calls the same way and produced an artifact with an empty denominator.

**The rejected set is measured, not guessed.** Rejected requests are not billed, so a probe
established it exactly, one keyword at a time against a known-good baseline, for $0.00:

===================  ==========  ===================================================
Keyword              Verdict     Note
===================  ==========  ===================================================
``maxItems``         rejected    "For 'array' type, property 'maxItems' is not supported"
``uniqueItems``      rejected    same shape
``minimum``          rejected    "For 'integer' type, property 'minimum' is not supported"
``maximum``          rejected    assumed with ``minimum``; not separately probed
free-form ``object`` rejected    every object must set ``additionalProperties: false``
``minItems``         accepted
``maxLength``        accepted
``minLength``        accepted
``pattern``          accepted
``format``           accepted
``enum``             accepted
``description``      accepted
``default``          accepted
partial ``required`` accepted    listing a subset of properties is fine
===================  ==========  ===================================================

**Validation, not sanitisation.** An earlier draft stripped the offending keywords on the
way out. That is worse than useless: it leaves the author believing a bound is enforced
while quietly removing it, and the plan cap is exactly the sort of bound whose silent loss
nobody notices until a model returns two hundred actions. So an unsupported construct
raises here, at build time, and the bound is re-stated in prose in the field description
and enforced after parsing where it always really lived (``BoundedPlanner._compile``).
"""

from __future__ import annotations

import contextlib
from typing import Any, Final

#: Keywords the API rejects outright. Measured; see the module docstring.
#:
#: ``maximum`` is included alongside ``minimum`` on the strength of the error naming the
#: type rather than the keyword. If that turns out to be wrong the cost is a schema that
#: is stricter than it needs to be, which is the safe direction to be wrong in.
UNSUPPORTED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"maxItems", "uniqueItems", "minimum", "maximum"}
)


class OutputSchemaError(ValueError):
    """A schema the structured-output API would reject.

    Raised while building the request, never after sending it. The point is to fail in a
    unit test that costs nothing rather than on the first call of a funded run.
    """


def validate_output_schema(schema: Any, *, path: str = "$") -> None:
    """Raise :class:`OutputSchemaError` if the API would refuse this schema.

    Walks the whole document, because the failure that started this was nested two levels
    down inside ``properties.actions.items`` and a top-level check would have missed it.
    """
    if isinstance(schema, list):
        for index, item in enumerate(schema):
            validate_output_schema(item, path=f"{path}[{index}]")
        return
    if not isinstance(schema, dict):
        return

    for keyword in sorted(UNSUPPORTED_KEYWORDS & set(schema)):
        raise OutputSchemaError(
            f"{path}: '{keyword}' is not supported by structured output. State the bound "
            f"in 'description' and enforce it after parsing instead."
        )

    if schema.get("type") == "object":
        if schema.get("additionalProperties") is not False:
            raise OutputSchemaError(
                f"{path}: an object must set 'additionalProperties': false. A free-form "
                f"object cannot be expressed; enumerate the properties instead."
            )
        if not schema.get("properties"):
            raise OutputSchemaError(
                f"{path}: an object with no 'properties' and additionalProperties false "
                f"can only ever be empty. This is almost certainly not what was meant."
            )

    for key, value in schema.items():
        if isinstance(value, dict | list):
            validate_output_schema(value, path=f"{path}.{key}")


#: Every argument name any registered operation accepts, with its type.
#:
#: Declared here rather than read from the tool registry because
#: ``tests/test_planner.py`` forbids anything under ``agentsec.agent`` from importing the
#: gateway, and the registry lives there. That boundary is the point of the architecture,
#: so the duplication is deliberate and ``tests/test_agent_schema.py`` asserts this set
#: equals the registry's exactly — the same arrangement the registry already has with the
#: Rego bundle.
#:
#: It exists at all because ``arguments`` was previously ``{"type": "object"}``, which the
#: API rejects: every object must close itself with ``additionalProperties: false``.
ACTION_ARGUMENT_PROPERTIES: Final[dict[str, dict[str, Any]]] = {
    "advisory_id": {"type": "string", "maxLength": 128},
    "body": {"type": "string", "maxLength": 4000},
    "cve_id": {"type": "string", "maxLength": 64},
    "description": {"type": "string", "maxLength": 4000},
    "ecosystem": {"type": "string", "maxLength": 64},
    "issue_key": {"type": "string", "maxLength": 64},
    "max_results": {"type": "integer"},
    "name": {"type": "string", "maxLength": 256},
    "path": {"type": "string", "maxLength": 512},
    "project": {"type": "string", "maxLength": 64},
    "pull_number": {"type": "integer"},
    "query": {"type": "string", "maxLength": 512},
    "ref": {"type": "string", "maxLength": 128},
    "remediation_id": {"type": "string", "maxLength": 128},
    "resource_id": {"type": "string", "maxLength": 256},
    "resource_type": {"type": "string", "maxLength": 64},
    "ruleset_id": {"type": "string", "maxLength": 128},
    "summary": {"type": "string", "maxLength": 512},
    "version": {"type": "string", "maxLength": 64},
}


#: Structured output rejects a schema with more than this many *optional* properties,
#: counted across the whole document. Measured by binary search against the live endpoint,
#: for $0.00, after "Schemas contains too many optional parameters (25)" killed the third
#: funded smoke attempt. Required properties do not count toward it: 42 all-required
#: passed the same probe.
MAX_OPTIONAL_PROPERTIES: Final = 12


def action_arguments_schema() -> dict[str, Any]:
    """The ``arguments`` sub-schema: a list of name/value pairs.

    The obvious shape — an object with one optional property per known argument name — is
    unavailable twice over. A free-form object is rejected outright, and a closed object
    enumerating all 19 names blows the 12-optional-property ceiling on its own, before the
    plan's other six optional fields are counted at all.

    So arguments travel as pairs. Nothing is optional, the valid names are enumerated in
    an ``enum`` (which is stricter than the object form, since a closed object still
    admits an empty one), and the shape costs zero against the ceiling however many
    arguments the registry grows to.

    The cost is that values arrive as strings, so integer-typed arguments need coercing on
    the way in — see :func:`arguments_from_pairs`. That is a real wart, and the honest
    alternative was not running the evaluation.
    """
    return {
        "type": "array",
        "description": "Arguments for the operation, as name/value pairs.",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "value"],
            "properties": {
                "name": {"type": "string", "enum": sorted(ACTION_ARGUMENT_PROPERTIES)},
                "value": {"type": "string", "maxLength": 4000},
            },
        },
    }


def arguments_from_pairs(raw: Any) -> dict[str, Any]:
    """Turn the wire shape back into the argument mapping the gateway expects.

    Integer-typed arguments are coerced using the registry's own types, because the
    gateway validates against ``argument_schema`` and a string where an integer belongs is
    a validation failure rather than a refusal — it would show up as an unscoreable case
    and quietly shrink the denominator.

    A value that will not coerce is kept as the original string rather than dropped. The
    gateway is the thing that decides what is acceptable; silently discarding an argument
    here would change the action the model actually proposed, which is the one thing the
    evaluation is measuring.
    """
    if isinstance(raw, dict):
        # Tolerated so a hand-written fixture, or a future model that ignores the pair
        # shape, still parses. The schema asks for pairs; this does not insist on them.
        return dict(raw)
    if not isinstance(raw, list):
        return {}

    arguments: dict[str, Any] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue
        value: Any = item.get("value")
        spec = ACTION_ARGUMENT_PROPERTIES.get(name)
        if spec is not None and spec.get("type") == "integer" and isinstance(value, str):
            with contextlib.suppress(ValueError):
                value = int(value.strip())
        arguments[name] = value
    return arguments


def count_optional_properties(schema: Any) -> int:
    """Total optional properties in a schema document, the way the API counts them."""
    if isinstance(schema, list):
        return sum(count_optional_properties(item) for item in schema)
    if not isinstance(schema, dict):
        return 0
    total = 0
    if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
        required = set(schema.get("required") or ())
        total += len([name for name in schema["properties"] if name not in required])
    for value in schema.values():
        if isinstance(value, dict | list):
            total += count_optional_properties(value)
    return total


__all__ = [
    "ACTION_ARGUMENT_PROPERTIES",
    "MAX_OPTIONAL_PROPERTIES",
    "UNSUPPORTED_KEYWORDS",
    "OutputSchemaError",
    "action_arguments_schema",
    "arguments_from_pairs",
    "count_optional_properties",
    "validate_output_schema",
]
