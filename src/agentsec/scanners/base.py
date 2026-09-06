"""Shared scanner contracts (AS-029, AS-030).

The rule both adapters exist to enforce:

    **No caller supplies a command.** Not the planner, not the workflow, not a test.

A scanner adapter that takes an argument list, a flags string, or an "extra options" field
is a remote code execution primitive wearing a typed interface. The planner is the least
trustworthy component in the system by design — it reads attacker-authored repository text
— and handing it any influence over an argv is the shortest path from prompt injection to
command execution.

So every adapter here builds its argv from an enumerated mode, a validated path, and a set
of allowlisted rule or scanner ids. There is no parameter through which anything else can
reach the process. ``tests/test_scanners.py`` asserts that structurally, by inspecting the
adapter signatures, because a code review is not a control.

Findings are normalised across both tools so the evaluation counts one kind of thing.
"""

from __future__ import annotations

import enum
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Final

#: A scan target inside the sandbox workspace. Relative, POSIX, no traversal.
_SAFE_PATH: Final = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/-]{0,511}$")


class ScannerError(Exception):
    """The scan could not be run, or its output could not be trusted."""


class InvalidTargetError(ScannerError):
    """The path is not a safe relative target inside the workspace."""


class UnknownRulesetError(ScannerError):
    """A ruleset or scanner id that is not on the allowlist. Fails closed."""


class Severity(enum.StrEnum):
    """Normalised severity.

    Both tools have their own scales and neither maps cleanly onto the other. Normalising
    here means the evaluation counts one kind of thing; leaving it to the report means two
    tools' ``HIGH`` silently mean different things in the same table.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return order[self.value]


@dataclass(frozen=True, slots=True)
class Finding:
    """One normalised result."""

    scanner: str
    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int | None = None
    identifier: str | None = None
    """A CVE, GHSA or check id where the tool provides one."""

    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    def key(self) -> tuple[str, str, str, int]:
        """Stable identity, for deduplication and for comparing runs."""
        return (self.scanner, self.rule_id, self.path, self.line or 0)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """What a scan produced, plus enough provenance to reproduce it.

    ``tool_version`` and ``database_version`` are recorded on every result, not assembled
    later for the report. A benchmark number whose scanner version is reconstructed from
    memory is a number nobody can check.
    """

    scanner: str
    tool_version: str
    findings: tuple[Finding, ...] = ()
    target: str = ""
    duration_seconds: float = 0.0
    truncated: bool = False
    database_version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.findings)

    def by_severity(self, minimum: Severity) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity.rank >= minimum.rank)

    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted({f.rule_id for f in self.findings}))


def safe_target(path: str) -> str:
    """Validate a scan target and return it in normalised form.

    Rejects absolute paths, traversal, and anything outside the workspace. The sandbox
    already confines the process, so this is defence in depth — but it is the layer that
    keeps a scan of ``../../etc`` from being a *coherent request*, which matters because
    an incoherent request that returns findings is one somebody will trust.
    """
    if not path or path in {".", "./"}:
        return "."
    candidate = path.replace("\\", "/").strip()
    if not _SAFE_PATH.match(candidate):
        raise InvalidTargetError(f"{path!r} is not a safe relative workspace path")
    normalised = posixpath.normpath(candidate)
    if normalised.startswith(("/", "../")) or normalised == "..":
        raise InvalidTargetError(f"{path!r} escapes the workspace")
    return normalised


def clamp(text: str, limit: int) -> tuple[str, bool]:
    """Bound a tool's output. Returns the text and whether anything was dropped.

    Scanner output is untrusted and unbounded: a repository crafted to produce a million
    findings is a denial-of-service against whatever parses them. The truncation flag is
    returned rather than logged so a result built from partial output is never mistaken
    for a complete one.
    """
    if len(text) <= limit:
        return text, False
    return text[:limit], True


__all__ = [
    "Finding",
    "InvalidTargetError",
    "ScanResult",
    "ScannerError",
    "Severity",
    "UnknownRulesetError",
    "clamp",
    "safe_target",
]
