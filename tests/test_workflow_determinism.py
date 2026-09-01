"""Structural determinism enforcement for workflow code (AS-020).

Workflow functions are re-executed from history on every replay — after a worker restart,
during a deploy, whenever Temporal recovers a task. Code that reads the clock, generates a
UUID, or touches the network takes a different branch the second time, and the divergence
surfaces as a non-determinism error *in the middle of the crash-recovery demo this project
exists to show off*.

A comment saying "no I/O here" does not survive the first person who needs a quick fix.
This module walks the workflow AST and fails if a banned construct appears.

As with the import-boundary check, the detector is tested against synthetic code first.
A scanner with a bug produces a green result that inspects nothing, which is the worst
outcome available for a check like this.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

WORKFLOW_MODULES = [
    pathlib.Path(__file__).resolve().parent.parent
    / "src"
    / "agentsec"
    / "workflows"
    / "security_review.py"
]

#: Calls that return a different answer on replay.
BANNED_CALLS = {
    "datetime.now": "use workflow.now()",
    "datetime.utcnow": "use workflow.now()",
    "time.time": "use workflow.now()",
    "time.monotonic": "use workflow.now()",
    "uuid.uuid4": "use workflow.uuid4()",
    "uuid.uuid1": "use workflow.uuid4()",
    "random.random": "use workflow.random()",
    "random.randint": "use workflow.random()",
    "random.choice": "use workflow.random()",
    "asyncio.sleep": "use workflow.sleep()",
    "os.urandom": "use workflow.random()",
    "secrets.token_hex": "use workflow.random()",
}

#: Modules whose presence in workflow code means I/O has leaked in.
BANNED_IMPORTS = {
    "httpx": "network access belongs in an activity",
    "requests": "network access belongs in an activity",
    "sqlalchemy": "database access belongs in an activity",
    "anthropic": "model calls belong in an activity",
    "random": "use workflow.random()",
    "secrets": "use workflow.random()",
    "agentsec.db": "database access belongs in an activity",
    "agentsec.gateway": "tool dispatch belongs in an activity",
    "agentsec.authz.engine": "policy evaluation belongs in an activity",
    "agentsec.authz.capabilities": "the workflow must never mint or verify authority",
}

#: Builtins that touch the filesystem.
BANNED_BUILTINS = {"open", "input", "print"}


def scan(source: str, filename: str = "<workflow>") -> list[str]:
    """Return a list of determinism violations in workflow source."""
    tree = ast.parse(source, filename=filename)
    problems: list[str] = []
    guarded = _guarded_import_lines(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            banned = _banned_call(name)
            if banned is not None:
                problems.append(f"line {node.lineno}: {name}() - {banned}")
            elif isinstance(node.func, ast.Name) and node.func.id in BANNED_BUILTINS:
                problems.append(f"line {node.lineno}: {node.func.id}() is not replay-safe")

        elif isinstance(node, ast.Import):
            for alias in node.names:
                problem = _banned_import(alias.name)
                if problem and node.lineno not in guarded:
                    problems.append(f"line {node.lineno}: import {alias.name} - {problem}")

        elif isinstance(node, ast.ImportFrom) and node.module:
            problem = _banned_import(node.module)
            if problem and node.lineno not in guarded:
                problems.append(f"line {node.lineno}: from {node.module} - {problem}")

    return problems


def _banned_call(name: str) -> str | None:
    """Match a dotted call name against the banned list, by suffix.

    Suffix rather than exact equality because the same call reaches the AST spelled
    several ways depending on how it was imported: ``datetime.now`` (from ``from datetime
    import datetime``), ``datetime.datetime.now`` (from ``import datetime``), or
    ``dt.datetime.now`` (aliased). An exact match catches only the first, which was the
    bug this scanner's own tests found — it would have passed a workflow calling
    ``datetime.datetime.now()`` straight through.

    ``workflow.now`` is unaffected: it does not end with ``.datetime.now``.
    """
    for banned, reason in BANNED_CALLS.items():
        if name == banned or name.endswith(f".{banned}"):
            return reason
    return None


def _banned_import(module: str) -> str | None:
    for banned, reason in BANNED_IMPORTS.items():
        if module == banned or module.startswith(f"{banned}."):
            return reason
    return None


def _guarded_import_lines(tree: ast.AST) -> set[int]:
    """Lines inside ``with workflow.unsafe.imports_passed_through():``.

    Temporal's sandbox allows pure data definitions through that guard. Imports there are
    a deliberate, reviewed exception rather than an oversight, so the scanner does not
    flag them — but it only exempts that exact construct.
    """
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            if "imports_passed_through" in ast.unparse(item.context_expr):
                for child in ast.walk(node):
                    if isinstance(child, ast.Import | ast.ImportFrom):
                        guarded.add(child.lineno)
    return guarded


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return f"{_call_name(func.value)}.{func.attr}".lstrip(".")
    if isinstance(func, ast.Name):
        return func.id
    return ""


# --------------------------------------------------------------- the detector works


@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ("import datetime\nx = datetime.datetime.now()", "datetime.now"),
        ("import uuid\nx = uuid.uuid4()", "uuid.uuid4"),
        ("import asyncio\nasync def f():\n    await asyncio.sleep(1)", "asyncio.sleep"),
        ("import time\nx = time.time()", "time.time"),
        ("x = open('/etc/passwd')", "open"),
        # The same call reaches the AST spelled several ways depending on how it was
        # imported. Exact matching caught only the first of these, which is the bug
        # these tests found.
        ("import datetime as dt\nx = dt.datetime.now()", "datetime.now"),
        ("from datetime import datetime\nx = datetime.now()", "datetime.now"),
        ("import random\nx = random.randint(1, 5)", "random.randint"),
    ],
)
def test_detector_catches_non_deterministic_calls(snippet: str, expected: str) -> None:
    """Proves the scan below inspects something."""
    problems = scan(snippet)
    assert any(expected in problem for problem in problems), problems


@pytest.mark.parametrize(
    "snippet",
    [
        "import httpx",
        "from sqlalchemy import select",
        "import agentsec.db",
        "from agentsec.gateway.core import McpGateway",
        "from agentsec.authz.capabilities import CapabilityMinter",
    ],
)
def test_detector_catches_io_imports(snippet: str) -> None:
    assert scan(snippet), f"expected a violation for: {snippet}"


def test_detector_allows_the_temporal_safe_equivalents() -> None:
    safe = (
        "from temporalio import workflow\n"
        "async def f():\n"
        "    now = workflow.now()\n"
        "    ident = workflow.uuid4()\n"
        "    await workflow.sleep(1)\n"
    )
    assert scan(safe) == []


def test_detector_respects_the_imports_passed_through_guard() -> None:
    """Pure data definitions are a deliberate, reviewed exception — but only inside that
    exact construct."""
    guarded = (
        "from temporalio import workflow\n"
        "with workflow.unsafe.imports_passed_through():\n"
        "    from agentsec.db.models import Run\n"
    )
    assert scan(guarded) == []

    unguarded = "from agentsec.db.models import Run\n"
    assert scan(unguarded), "an unguarded I/O import must still be caught"


# --------------------------------------------------------------- the rule holds


@pytest.mark.parametrize("path", WORKFLOW_MODULES, ids=lambda p: p.name)
def test_workflow_module_is_replay_safe(path: pathlib.Path) -> None:
    problems = scan(path.read_text(encoding="utf-8"), filename=str(path))
    assert problems == [], f"{path.name} contains non-deterministic constructs:\n  " + "\n  ".join(
        problems
    )


def test_workflow_modules_are_actually_being_scanned() -> None:
    """Guards against the list of modules quietly emptying, which would make the check
    above pass by examining nothing."""
    assert WORKFLOW_MODULES
    for path in WORKFLOW_MODULES:
        assert path.exists(), path
        assert "@workflow.defn" in path.read_text(encoding="utf-8")
