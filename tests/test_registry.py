"""Trusted tool registry tests (AS-013).

The most valuable test here is the last section: the registry and the Rego policy each
enumerate tool operations independently, and nothing but a test stops them drifting apart.

They are kept as *two* enumerations deliberately. A design where the policy derived its
allow-list from the registry would mean adding a registry entry silently granted policy
permission; requiring both means a real addition is a deliberate change in two places,
while an accidental divergence fails here.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from agentsec.authz.models import RiskClass
from agentsec.gateway.registry import (
    RegistryError,
    ToolDefinition,
    ToolRegistry,
    UnknownToolError,
    load_registry,
)

pytestmark = pytest.mark.authz

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "registry" / "tools.json"
POLICY_PATH = REPO_ROOT / "policy" / "agentsec" / "authz.rego"


@pytest.fixture(scope="module")
def registry() -> ToolRegistry:
    return load_registry(REGISTRY_PATH)


def valid_entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "tool": "fixture_repo",
        "operation": "read_file",
        "description": "Read a file.",
        "risk_class": "read_only",
        "resource_schemes": ["fixture"],
        "required_scopes": ["repo:read"],
        "requires_approval": False,
        "idempotent": True,
        "result_trust": "untrusted",
        "timeout_seconds": 10.0,
        "max_result_bytes": 1024,
    }
    return {**base, **overrides}


# --------------------------------------------------------------------------- loading


def test_the_shipped_registry_loads(registry: ToolRegistry) -> None:
    assert len(registry) >= 20
    assert registry.version == "1.0.0"


def test_lookup_resolves_a_known_operation(registry: ToolRegistry) -> None:
    definition = registry.lookup("fixture_repo", "read_file")
    assert definition.risk_class is RiskClass.READ_ONLY
    assert definition.requires_approval is False


def test_unknown_tool_fails_closed(registry: ToolRegistry) -> None:
    """There is no default tool. A miss raises rather than returning something
    permissive that a caller might use."""
    with pytest.raises(UnknownToolError):
        registry.lookup("mystery_tool", "read_file")


def test_unknown_operation_on_a_known_tool_fails_closed(registry: ToolRegistry) -> None:
    with pytest.raises(UnknownToolError):
        registry.lookup("fixture_repo", "exfiltrate")


def test_missing_registry_file_is_fatal(tmp_path: pathlib.Path) -> None:
    with pytest.raises(RegistryError, match="not found"):
        load_registry(tmp_path / "nope.json")


def test_malformed_json_is_fatal(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "tools.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RegistryError, match="not valid JSON"):
        load_registry(path)


def test_empty_registry_is_fatal(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"version": "1", "entries": []}), encoding="utf-8")
    with pytest.raises(RegistryError, match="empty"):
        load_registry(path)


def test_one_bad_entry_fails_the_whole_load(tmp_path: pathlib.Path) -> None:
    """Strict by design. Skipping a malformed entry would leave that tool undefined at
    dispatch time, and undefined is a state somebody eventually handles by guessing."""
    path = tmp_path / "tools.json"
    path.write_text(
        json.dumps({"version": "1", "entries": [valid_entry(), valid_entry(required_scopes=[])]}),
        encoding="utf-8",
    )
    with pytest.raises(RegistryError, match="invalid registry entry"):
        load_registry(path)


def test_duplicate_entries_are_rejected() -> None:
    entry = ToolDefinition.model_validate(valid_entry())
    with pytest.raises(RegistryError, match="duplicate"):
        ToolRegistry([entry, entry], version="1")


# --------------------------------------------------------------------------- validation


def test_wildcards_are_rejected_in_schemes() -> None:
    """A wildcard is how a registry grows access nobody reviewed."""
    with pytest.raises(ValueError, match="wildcard"):
        ToolDefinition.model_validate(valid_entry(resource_schemes=["*"]))


def test_wildcards_are_rejected_in_scopes() -> None:
    with pytest.raises(ValueError, match="wildcard"):
        ToolDefinition.model_validate(valid_entry(required_scopes=["repo:*"]))


def test_a_scopeless_entry_is_rejected() -> None:
    """A tool requiring no scope could be invoked by any capability."""
    with pytest.raises(ValueError, match="at least one scope"):
        ToolDefinition.model_validate(valid_entry(required_scopes=[]))


def test_a_schemeless_entry_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one resource scheme"):
        ToolDefinition.model_validate(valid_entry(resource_schemes=[]))


def test_secret_access_cannot_be_registered() -> None:
    """Policy denies the class unconditionally, so such an entry could never be invoked.
    A dead entry that looks live is worse than a loud failure."""
    with pytest.raises(ValueError, match="always denied by policy"):
        ToolDefinition.model_validate(
            valid_entry(risk_class="secret_access", requires_approval=True)
        )


def test_a_mutating_entry_must_require_approval() -> None:
    with pytest.raises(ValueError, match="must require approval"):
        ToolDefinition.model_validate(
            valid_entry(risk_class="high_risk_write", requires_approval=False)
        )


def test_a_read_only_entry_must_not_require_approval() -> None:
    """Approval fatigue is what makes operators rubber-stamp the ones that matter."""
    with pytest.raises(ValueError, match="should not require approval"):
        ToolDefinition.model_validate(valid_entry(requires_approval=True))


def test_no_tool_result_may_be_marked_trusted() -> None:
    """Backend responses are attacker-influenced by definition."""
    with pytest.raises(ValueError, match="no tool result is trusted"):
        ToolDefinition.model_validate(valid_entry(result_trust="trusted"))


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValueError):
        ToolDefinition.model_validate(valid_entry(sudo=True))


def test_entries_are_immutable() -> None:
    definition = ToolDefinition.model_validate(valid_entry())
    with pytest.raises(ValueError):
        definition.requires_approval = True  # type: ignore[misc]


# --------------------------------------------------------------------------- hashing


def test_registry_hash_is_stable(registry: ToolRegistry) -> None:
    assert load_registry(REGISTRY_PATH).hash == registry.hash
    assert len(registry.hash) == 64


def test_registry_hash_changes_with_content(tmp_path: pathlib.Path) -> None:
    """The hash is bound into capability grants, so a registry change invalidates
    outstanding authority minted under the previous one."""
    base = {"version": "1", "entries": [valid_entry()]}
    changed = {
        "version": "1",
        "entries": [valid_entry(risk_class="high_risk_write", requires_approval=True)],
    }

    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    first.write_text(json.dumps(base), encoding="utf-8")
    second.write_text(json.dumps(changed), encoding="utf-8")

    assert load_registry(first).hash != load_registry(second).hash


def test_registry_hash_ignores_entry_order(tmp_path: pathlib.Path) -> None:
    """Reordering the file is not a content change and must not invalidate grants."""
    a = valid_entry()
    b = valid_entry(operation="list_files")

    forward = tmp_path / "f.json"
    reverse = tmp_path / "r.json"
    forward.write_text(json.dumps({"version": "1", "entries": [a, b]}), encoding="utf-8")
    reverse.write_text(json.dumps({"version": "1", "entries": [b, a]}), encoding="utf-8")

    assert load_registry(forward).hash == load_registry(reverse).hash


def test_registry_hash_includes_the_version(tmp_path: pathlib.Path) -> None:
    one = tmp_path / "1.json"
    two = tmp_path / "2.json"
    one.write_text(json.dumps({"version": "1.0.0", "entries": [valid_entry()]}), encoding="utf-8")
    two.write_text(json.dumps({"version": "2.0.0", "entries": [valid_entry()]}), encoding="utf-8")
    assert load_registry(one).hash != load_registry(two).hash


# --------------------------------------------------------------- registry vs policy


def parse_rego_operation_sets(source: str, name: str) -> dict[str, set[str]]:
    """Extract a ``name := {"tool": {"op", ...}, ...}`` block from the Rego source.

    A deliberately narrow parser for one known shape. It asserts it found something,
    because a parser that silently returns nothing turns this into a test that passes by
    inspecting no data at all.
    """
    match = re.search(rf"^{re.escape(name)} := \{{(.*?)^\}}", source, re.M | re.S)
    assert match, f"could not find {name} in the policy source"

    parsed: dict[str, set[str]] = {}
    for tool, operations in re.findall(r'"([a-z_]+)":\s*\{([^}]*)\}', match.group(1), re.S):
        parsed[tool] = set(re.findall(r'"([a-z_]+)"', operations))
    assert parsed, f"parsed {name} but found no entries"
    return parsed


@pytest.fixture(scope="module")
def policy_source() -> str:
    return POLICY_PATH.read_text(encoding="utf-8")


def test_the_rego_parser_actually_works(policy_source: str) -> None:
    """Proves the cross-checks below inspect real data."""
    reads = parse_rego_operation_sets(policy_source, "read_operations")
    assert "fixture_repo" in reads
    assert "read_file" in reads["fixture_repo"]


def test_every_registry_read_is_permitted_by_policy(
    registry: ToolRegistry, policy_source: str
) -> None:
    """A registered read the policy does not know about would be denied at runtime — a
    tool that exists, validates, and never works."""
    policy_reads = parse_rego_operation_sets(policy_source, "read_operations")
    for entry in registry.entries():
        if entry.is_mutating:
            continue
        assert entry.operation in policy_reads.get(entry.tool, set()), (
            f"{entry.qualified_name} is registered as a read but the policy does not allow it"
        )


def test_every_registry_mutation_is_approval_gated_by_policy(
    registry: ToolRegistry, policy_source: str
) -> None:
    policy_approvals = parse_rego_operation_sets(policy_source, "approval_operations")
    for entry in registry.entries():
        if not entry.is_mutating:
            continue
        assert entry.operation in policy_approvals.get(entry.tool, set()), (
            f"{entry.qualified_name} is a registered mutation but the policy does not "
            "route it through approval"
        )


def test_no_registry_entry_is_on_the_policy_forbidden_list(
    registry: ToolRegistry, policy_source: str
) -> None:
    """The sharpest drift case: an operation the policy forbids should not be registered
    as invokable at all."""
    forbidden = parse_rego_operation_sets(policy_source, "forbidden_operations")
    for entry in registry.entries():
        assert entry.operation not in forbidden.get(entry.tool, set()), (
            f"{entry.qualified_name} is registered but explicitly forbidden by policy"
        )


def test_registry_schemes_match_the_policy_scheme_bindings(
    registry: ToolRegistry, policy_source: str
) -> None:
    """Guards the confused-deputy fix from the other side: if the registry lets a tool
    address a scheme the policy does not bind to it, every such call fails at runtime."""
    bindings = parse_rego_operation_sets(policy_source, "tool_schemes")
    for entry in registry.entries():
        allowed = bindings.get(entry.tool, set())
        assert allowed, f"{entry.tool} has no scheme binding in the policy"
        for scheme in entry.resource_schemes:
            assert scheme in allowed, (
                f"{entry.qualified_name} may address {scheme}:// per the registry, "
                "but the policy does not bind that scheme to this tool"
            )
