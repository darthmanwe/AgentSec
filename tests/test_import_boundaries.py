"""Structural enforcement of the core invariant (AS-011).

    The LLM may reason, propose actions, and request capabilities. It must never
    authorize itself, mint authority, or directly execute consequential external
    side effects.

Convention cannot enforce that. A comment saying "do not import the minter here" survives
exactly until someone needs a quick fix at 2am. This module builds the real import graph
from source and asserts the boundary holds — including transitively, because
``agent -> helpers -> capabilities`` is just as much a breach as a direct import.

The checker is itself tested against a synthetic graph. Without that, a bug in the graph
builder would produce a test that passes because it inspects nothing, which is the worst
possible outcome for a security check.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"
PACKAGE = "agentsec"

#: Modules the planner must never be able to reach, and why.
FORBIDDEN_FROM_AGENT = {
    "agentsec.authz.capabilities": "the planner must never mint authority",
    "agentsec.authz.keys": "the planner must never touch signing key material",
    "agentsec.authz.approvals": "the planner must never grant or resolve its own approval",
}

#: Package prefixes considered "the planner side" of the boundary.
AGENT_PREFIXES = ("agentsec.agent",)


def module_name(path: pathlib.Path) -> str:
    relative = path.relative_to(SRC).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def direct_imports(path: pathlib.Path) -> set[str]:
    """First-party modules imported by one file, resolved to absolute names."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(PACKAGE):
                    found.add(alias.name)
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.level == 0
            and node.module.startswith(PACKAGE)
        ):
            found.add(node.module)
            # `from agentsec.authz import capabilities` imports a submodule, which a
            # naive reading would record only as `agentsec.authz`.
            for alias in node.names:
                found.add(f"{node.module}.{alias.name}")
    return found


def build_graph() -> dict[str, set[str]]:
    return {module_name(path): direct_imports(path) for path in sorted(SRC.rglob("*.py"))}


def reachable_from(graph: dict[str, set[str]], start: str) -> set[str]:
    """Every module transitively importable from ``start``."""
    seen: set[str] = set()
    stack = [start]
    while stack:
        current = stack.pop()
        for target in graph.get(current, set()):
            if target not in seen:
                seen.add(target)
                stack.append(target)
    return seen


@pytest.fixture(scope="module")
def graph() -> dict[str, set[str]]:
    return build_graph()


# --------------------------------------------------------------- the checker works


def test_detector_catches_a_direct_violation() -> None:
    """Proves the mechanism, so a green result below means something."""
    synthetic = {
        "agentsec.agent.planner": {"agentsec.authz.capabilities"},
        "agentsec.authz.capabilities": set(),
    }
    assert "agentsec.authz.capabilities" in reachable_from(synthetic, "agentsec.agent.planner")


def test_detector_catches_a_transitive_violation() -> None:
    """`agent -> helpers -> capabilities` is as much a breach as a direct import, and is
    the form the violation would actually take in practice."""
    synthetic = {
        "agentsec.agent.planner": {"agentsec.agent.helpers"},
        "agentsec.agent.helpers": {"agentsec.authz.capabilities"},
        "agentsec.authz.capabilities": set(),
    }
    assert "agentsec.authz.capabilities" in reachable_from(synthetic, "agentsec.agent.planner")


def test_detector_does_not_cry_wolf() -> None:
    synthetic = {
        "agentsec.agent.planner": {"agentsec.authz.models"},
        "agentsec.authz.models": set(),
    }
    assert "agentsec.authz.capabilities" not in reachable_from(synthetic, "agentsec.agent.planner")


def test_graph_covers_the_real_source_tree(graph: dict[str, set[str]]) -> None:
    """Guards against the graph builder silently finding nothing."""
    assert "agentsec.authz.capabilities" in graph
    assert "agentsec.authz.models" in graph.get("agentsec.authz.digest", set())


# --------------------------------------------------------------- the boundary holds


def test_planner_cannot_reach_privileged_modules(graph: dict[str, set[str]]) -> None:
    """The invariant, enforced mechanically.

    Vacuous until AS-025/AS-026 create ``agentsec.agent`` — and deliberately written to
    start enforcing the moment that package appears, rather than needing to be remembered
    then.
    """
    agent_modules = [m for m in graph if m.startswith(AGENT_PREFIXES)]
    for module in agent_modules:
        reachable = reachable_from(graph, module)
        for forbidden, why in FORBIDDEN_FROM_AGENT.items():
            assert forbidden not in reachable, f"{module} can reach {forbidden}: {why}"


def test_authorization_does_not_depend_on_the_planner(graph: dict[str, set[str]]) -> None:
    """No reverse coupling. Authorization must be verifiable without the model existing —
    which is also what lets the whole kernel be tested with no API key."""
    for module, imports in graph.items():
        if not module.startswith("agentsec.authz"):
            continue
        offending = {target for target in imports if target.startswith(AGENT_PREFIXES)}
        assert not offending, f"{module} imports planner code: {offending}"


def test_authorization_kernel_has_no_llm_dependency(graph: dict[str, set[str]]) -> None:
    """The S1 gate as a structural property rather than a runtime observation."""
    for module in graph:
        if not module.startswith("agentsec.authz"):
            continue
        source = SRC / pathlib.Path(*module.split(".")).with_suffix(".py")
        if not source.exists():
            source = SRC / pathlib.Path(*module.split(".")) / "__init__.py"
        text = source.read_text(encoding="utf-8")
        for banned in ("import anthropic", "from anthropic", "import langgraph", "from langgraph"):
            assert banned not in text, f"{module} pulls in an LLM dependency: {banned}"


def test_minter_is_not_re_exported_from_the_package_root() -> None:
    """Reaching the minter should require naming the module it lives in. Convenience
    re-exports are how a boundary quietly stops being one."""
    root = (SRC / "agentsec" / "__init__.py").read_text(encoding="utf-8")
    assert "CapabilityMinter" not in root
    authz_init = (SRC / "agentsec" / "authz" / "__init__.py").read_text(encoding="utf-8")
    assert "CapabilityMinter" not in authz_init


def test_verifier_does_not_import_the_minter_key_material(graph: dict[str, set[str]]) -> None:
    """The gateway verifies on every call; it must not hold anything that could sign.

    Ed25519 already gives this asymmetry — the verifier holds only public material — but
    asserting it means a later refactor to a shared HMAC secret fails here rather than
    quietly handing minting power to every verifier.
    """
    source = (SRC / "agentsec" / "authz" / "capabilities.py").read_text(encoding="utf-8")
    assert "Ed25519PrivateKey" not in source, (
        "capabilities.py should take a SigningKey, never construct private key material"
    )
