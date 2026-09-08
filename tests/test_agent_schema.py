"""Structured-output schema rules (AS-040).

Every assertion here corresponds to a live 400 that cost a funded smoke run all 22 of its
calls. The point of the file is that none of it needs an API key: the rules were measured
once, against the real endpoint, and are asserted for free from then on.
"""

from __future__ import annotations

import asyncio
import json
import pathlib

import pytest

from agentsec.agent.planner import ACTION_PLAN_SCHEMA, MAX_ACTIONS
from agentsec.agent.provider import Message, ModelRequest
from agentsec.agent.providers import MockProvider
from agentsec.agent.schema import (
    ACTION_ARGUMENT_PROPERTIES,
    MAX_OPTIONAL_PROPERTIES,
    UNSUPPORTED_KEYWORDS,
    OutputSchemaError,
    action_arguments_schema,
    arguments_from_pairs,
    count_optional_properties,
    validate_output_schema,
)

pytestmark = pytest.mark.authz

REGISTRY_PATH = pathlib.Path(__file__).resolve().parents[1] / "registry" / "tools.json"


def _closed(properties: dict[str, object]) -> dict[str, object]:
    return {"type": "object", "additionalProperties": False, "properties": properties}


# --------------------------------------------------------------------------- rules


@pytest.mark.parametrize("keyword", sorted(UNSUPPORTED_KEYWORDS))
def test_every_unsupported_keyword_is_rejected(keyword: str) -> None:
    schema = _closed({"a": {"type": "array", "items": {"type": "string"}, keyword: 1}})
    with pytest.raises(OutputSchemaError, match=keyword):
        validate_output_schema(schema)


def test_rejection_reaches_nested_positions() -> None:
    """The failure that started this was two levels down, inside ``actions.items``.

    A top-level-only check would have passed it through to the API.
    """
    schema = _closed(
        {
            "actions": {
                "type": "array",
                "items": _closed({"tags": {"type": "array", "maxItems": 5}}),
            }
        }
    )
    with pytest.raises(OutputSchemaError, match=r"\$\.properties\.actions\.items"):
        validate_output_schema(schema)


def test_open_object_is_rejected() -> None:
    with pytest.raises(OutputSchemaError, match="additionalProperties"):
        validate_output_schema(_closed({"arguments": {"type": "object"}}))


def test_closed_but_empty_object_is_rejected() -> None:
    """Closing an object with no properties makes it permanently empty.

    That silently removes the field rather than fixing it, which is the failure mode this
    module exists to refuse.
    """
    with pytest.raises(OutputSchemaError, match="can only ever be empty"):
        validate_output_schema(
            _closed({"arguments": {"type": "object", "additionalProperties": False}})
        )


@pytest.mark.parametrize(
    "keyword,value",
    [
        ("maxLength", 10),
        ("minLength", 1),
        ("minItems", 1),
        ("pattern", "^x"),
        ("enum", ["a", "b"]),
        ("description", "text"),
        ("default", "x"),
    ],
)
def test_supported_keywords_pass(keyword: str, value: object) -> None:
    """The complement matters too: over-strict validation would remove real constraints."""
    validate_output_schema(_closed({"a": {"type": "string", keyword: value}}))


# --------------------------------------------------------------------------- the plan schema


def test_action_plan_schema_would_be_accepted() -> None:
    validate_output_schema(ACTION_PLAN_SCHEMA)


def test_action_plan_schema_carries_no_unsupported_keyword_anywhere() -> None:
    """Belt and braces, by text rather than by walk, so a new nesting shape cannot hide one."""
    rendered = json.dumps(ACTION_PLAN_SCHEMA)
    for keyword in UNSUPPORTED_KEYWORDS:
        assert f'"{keyword}"' not in rendered


def test_plan_bound_is_stated_even_though_it_cannot_be_enforced_in_schema() -> None:
    """``maxItems`` is gone, so the cap must still reach the model somehow."""
    actions = ACTION_PLAN_SCHEMA["properties"]["actions"]  # type: ignore[index]
    assert str(MAX_ACTIONS) in actions["description"]


def test_plan_bound_is_still_enforced_after_parsing() -> None:
    """The schema no longer bounds the array, so the post-parse cap is now load-bearing.

    If this ever regresses, an unbounded plan reaches the control path.
    """
    from agentsec.agent.state import ProposedAction, SecurityAgentState

    state = SecurityAgentState(run_id="r", task="t", repository="fixture://repo-a")
    state.proposed = [
        ProposedAction(tool="fixture_repo", operation="list_files", resource="fixture://repo-a")
        for _ in range(MAX_ACTIONS + 25)
    ]
    from agentsec.agent.planner import BoundedPlanner

    asyncio.run(BoundedPlanner._compile({"state": state}))
    assert len(state.proposed) == MAX_ACTIONS


# --------------------------------------------------------------------------- registry parity


def test_argument_names_match_the_registry_exactly() -> None:
    """The planner may not import the gateway, so this set is duplicated by design.

    Duplication is safe only while something checks it, which is this test. Same
    arrangement the tool registry already has with the Rego bundle.
    """
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    from_registry: dict[str, str] = {}
    for entry in registry["entries"]:
        for name, spec in (entry.get("argument_schema", {}).get("properties") or {}).items():
            from_registry[name] = spec.get("type", "string")

    assert set(ACTION_ARGUMENT_PROPERTIES) == set(from_registry), (
        "the planner's argument union has drifted from registry/tools.json"
    )
    for name, expected in from_registry.items():
        assert ACTION_ARGUMENT_PROPERTIES[name]["type"] == expected, name


def test_arguments_sub_schema_is_valid_and_costs_no_optional_properties() -> None:
    """The pair shape exists precisely to spend nothing against the optional ceiling."""
    schema = action_arguments_schema()
    validate_output_schema(schema)
    assert count_optional_properties(schema) == 0


def test_arguments_sub_schema_enumerates_exactly_the_known_names() -> None:
    names = action_arguments_schema()["items"]["properties"]["name"]["enum"]
    assert set(names) == set(ACTION_ARGUMENT_PROPERTIES)


def test_arguments_sub_schema_is_a_copy() -> None:
    """Mutating one request's schema must not edit the module-level table."""
    first = action_arguments_schema()
    first["items"]["properties"]["value"]["maxLength"] = 1
    assert action_arguments_schema()["items"]["properties"]["value"]["maxLength"] != 1


def test_plan_schema_stays_under_the_optional_ceiling() -> None:
    """The limit that killed the third smoke attempt, asserted for free from now on."""
    assert count_optional_properties(ACTION_PLAN_SCHEMA) <= MAX_OPTIONAL_PROPERTIES


# --------------------------------------------------------------------------- pair decoding


def test_pairs_become_a_mapping() -> None:
    assert arguments_from_pairs(
        [{"name": "path", "value": "src/main.py"}, {"name": "query", "value": "sql"}]
    ) == {"path": "src/main.py", "query": "sql"}


def test_integer_arguments_are_coerced_from_their_string_form() -> None:
    """The gateway validates against the registry, where these are integers.

    Left as strings they would fail argument validation and be recorded as unscoreable —
    shrinking the denominator for a reason that has nothing to do with the model.
    """
    assert arguments_from_pairs([{"name": "pull_number", "value": "42"}]) == {"pull_number": 42}


def test_an_uncoercible_integer_is_kept_not_dropped() -> None:
    """Dropping it would change the action the model actually proposed.

    Whether it is acceptable is the gateway's decision, not the parser's.
    """
    assert arguments_from_pairs([{"name": "pull_number", "value": "abc"}]) == {
        "pull_number": "abc"
    }


def test_a_plain_mapping_still_parses() -> None:
    """Tolerated so fixtures and any future non-pair output are not a hard failure."""
    assert arguments_from_pairs({"path": "x"}) == {"path": "x"}


@pytest.mark.parametrize("junk", [None, "text", 7, [1, 2], [{"value": "no name"}]])
def test_malformed_pairs_yield_no_arguments_rather_than_raising(junk: object) -> None:
    assert arguments_from_pairs(junk) == {}


# --------------------------------------------------------------------------- providers


def test_mock_provider_is_as_strict_as_the_api() -> None:
    """The reason the dry run missed this: the mock accepted anything.

    A rehearsal that accepts a schema the API refuses is not rehearsing the funded run.
    """
    request = ModelRequest(
        model="claude-haiku-4-5-20251001",
        system="s",
        messages=[Message(role="user", content="x")],
        output_schema=_closed({"a": {"type": "array", "maxItems": 3}}),
    )
    with pytest.raises(OutputSchemaError):
        asyncio.run(MockProvider().complete(request))


def test_live_payload_builder_refuses_before_dispatch() -> None:
    from agentsec.agent.provider import build_payload

    request = ModelRequest(
        model="claude-haiku-4-5-20251001",
        system="s",
        messages=[Message(role="user", content="x")],
        output_schema=_closed({"a": {"type": "array", "maxItems": 3}}),
    )
    with pytest.raises(OutputSchemaError):
        build_payload(request)


# --------------------------------------------------------------------------- cost attribution


def test_a_cached_response_costs_nothing_now() -> None:
    """A resume must not be charged for calls it replayed rather than made."""
    from agentsec.agent.provider import ModelResponse, Usage, response_usd

    replayed = ModelResponse(
        model="claude-haiku-4-5-20251001",
        text="{}",
        usage=Usage(input_tokens=10_000, output_tokens=10_000),
        provider="anthropic",
        metadata={"cached": True, "original_usd": 0.06},
    )
    assert response_usd(replayed) == 0.0


def test_a_live_response_is_priced_from_the_capability_table() -> None:
    from agentsec.agent.provider import ModelResponse, Usage, response_usd

    live = ModelResponse(
        model="claude-haiku-4-5-20251001",
        text="{}",
        usage=Usage(input_tokens=1_000_000, output_tokens=1_000_000),
        provider="anthropic",
    )
    assert response_usd(live) == pytest.approx(6.0)  # $1/MTok in + $5/MTok out


def test_an_unpriceable_model_reports_zero_rather_than_raising() -> None:
    """Attribution is not the authority on spend; the accountant is.

    An alias repointed to a snapshot the table has never seen must not abort a paid run
    that is otherwise proceeding correctly.
    """
    from agentsec.agent.provider import ModelResponse, Usage, response_usd

    unknown = ModelResponse(
        model="claude-something-unreleased",
        text="{}",
        usage=Usage(input_tokens=100, output_tokens=100),
        provider="anthropic",
    )
    assert response_usd(unknown) == 0.0
