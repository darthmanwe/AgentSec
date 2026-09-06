"""The MCP servers must never write to stdout (AS-015, AS-021).

stdout *is* the protocol stream over stdio transport. A single stray ``print`` — a
leftover debug line, a library that chatters on startup — interleaves with JSON-RPC frames
and corrupts the session, usually as a parse error somewhere unrelated to the line that
caused it.

Ruff's T20 rule enforces this project-wide, which was enough until AS-021 needed a CLI
that legitimately prints. That exception is scoped to ``src/agentsec/cli/``, but a
per-file-ignore list is a configuration file: it can be widened by someone who does not
know why the rule exists. This test states the guarantee where it actually matters, so
weakening the lint configuration does not silently weaken the protocol.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SERVERS = sorted(
    (pathlib.Path(__file__).resolve().parent.parent / "src" / "agentsec" / "mcp_servers").glob(
        "*.py"
    )
)

#: Writing to these corrupts the JSON-RPC stream. ``sys.stderr`` is fine and is what the
#: servers use for diagnostics.
BANNED = {"print", "sys.stdout.write", "sys.stdout.writelines", "sys.stdout.flush"}


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return f"{_call_name(func.value)}.{func.attr}".lstrip(".")
    if isinstance(func, ast.Name):
        return func.id
    return ""


def stdout_writes(source: str) -> list[str]:
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in BANNED:
                found.append(f"line {node.lineno}: {name}()")
    return found


@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ("print('hello')", "print"),
        ("import sys\nsys.stdout.write('x')", "sys.stdout.write"),
    ],
)
def test_the_detector_finds_stdout_writes(snippet: str, expected: str) -> None:
    """Proves the scan below inspects something. A detector with a bug produces a green
    result that checked nothing, which is worse than no check at all."""
    assert any(expected in problem for problem in stdout_writes(snippet))


def test_the_detector_allows_stderr() -> None:
    assert stdout_writes("import sys\nsys.stderr.write('diagnostic')") == []


@pytest.mark.parametrize("path", SERVERS, ids=lambda p: p.name)
def test_no_mcp_server_writes_to_stdout(path: pathlib.Path) -> None:
    problems = stdout_writes(path.read_text(encoding="utf-8"))
    assert problems == [], f"{path.name} would corrupt the MCP stream:\n  " + "\n  ".join(problems)


def test_the_servers_are_actually_being_scanned() -> None:
    """Guards against the glob quietly matching nothing, which would make the check above
    pass by examining an empty list."""
    assert len(SERVERS) >= 4, [p.name for p in SERVERS]
