"""Reconstruct a run from its audit trail, and check the invariant against it (AS-041).

This is the part of observability that earns its place in a security project. Metrics say
how often something happened; replay says whether what happened was allowed, and it says
so **without consulting the code that allowed it**.

That independence is the whole point. If :mod:`agentsec.control.pipeline` has a bug that
lets an action through, a log written by that same pipeline will faithfully record the
action as authorized — the log and the bug agree, because they share an author. Replay
instead reads the trail and re-derives the verdict from first principles:

    An execution is justified only if, earlier in the same trail and for the same
    action digest, there is an ALLOW — or a REQUIRE_APPROVAL followed by a granted
    approval — and a redeemed capability.

Anything else is a violation, whatever the pipeline believed. The check is deliberately
stricter than "the pipeline said yes".

**A gap is a violation too.** An execution with no preceding events at all is reported
rather than skipped: the most likely way for a trail to show a clean run is for the
enforcement path to have stopped writing to it. Silence is the failure mode to be most
suspicious of, so it is the one this module refuses to read as success.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from agentsec.observability.audit import AuditEventType, AuditRecord

#: Outcomes that authorize on their own.
_ALLOWING: frozenset[str] = frozenset({"ALLOW", "allow"})

#: Outcomes that authorize only once an approval is granted for the same digest.
_CONDITIONAL: frozenset[str] = frozenset({"REQUIRE_APPROVAL", "require_approval"})

#: What a granted approval looks like.
_GRANTED: frozenset[str] = frozenset({"granted", "GRANTED", "approved", "APPROVED"})


@dataclass
class ActionHistory:
    """Everything the trail says about one action digest, in order."""

    action_digest: str
    records: list[AuditRecord] = field(default_factory=list)

    @property
    def tool(self) -> str | None:
        return next((r.tool for r in self.records if r.tool), None)

    @property
    def operation(self) -> str | None:
        return next((r.operation for r in self.records if r.operation), None)

    @property
    def executed(self) -> bool:
        return self.execution_count > 0

    @property
    def execution_count(self) -> int:
        return sum(1 for r in self.records if r.event_type is AuditEventType.EXECUTED)

    def attempts(self) -> list[list[AuditRecord]]:
        """Split the history into one authorization attempt per compile.

        The same action proposed twice produces the *same digest* — that is the point of
        a canonical digest — so a repeated run interleaves several complete attempts under
        one history. Without this split, an approval recorded during the first attempt
        would appear to justify an execution in the third, and only the first execution
        would be examined at all. Both are ways for a real violation to read as sound.

        ``ACTION_COMPILED`` marks the start of an attempt because it is emitted once per
        traversal, immediately after the digest exists.
        """
        segments: list[list[AuditRecord]] = []
        current: list[AuditRecord] = []
        for record in self.records:
            if record.event_type is AuditEventType.ACTION_COMPILED and current:
                segments.append(current)
                current = []
            current.append(record)
        if current:
            segments.append(current)
        return segments

    def first(self, event_type: AuditEventType) -> AuditRecord | None:
        return next((r for r in self.records if r.event_type is event_type), None)

    def outcome_of(self, event_type: AuditEventType) -> str | None:
        record = self.first(event_type)
        return record.outcome if record else None

    def timeline(self) -> list[str]:
        """A human-readable trace, for the demo and for a failing test's message."""
        lines = []
        for record in self.records:
            parts = [record.occurred_at.isoformat(timespec="milliseconds"), record.event_type.value]
            if record.outcome:
                parts.append(f"-> {record.outcome}")
            if record.reason:
                parts.append(f"({record.reason})")
            lines.append(" ".join(parts))
        return lines


@dataclass(frozen=True, slots=True)
class Violation:
    """An execution the trail does not justify."""

    action_digest: str
    reason: str
    tool: str | None = None
    operation: str | None = None

    def __str__(self) -> str:
        target = f"{self.tool}.{self.operation}" if self.tool else "unknown action"
        return f"{target} [{self.action_digest[:12]}]: {self.reason}"


@dataclass
class Reconstruction:
    """A whole run, rebuilt."""

    histories: list[ActionHistory] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    orphaned: list[AuditRecord] = field(default_factory=list)
    """Records carrying no action digest — plan-level events, and anything malformed."""

    @property
    def executed(self) -> int:
        """Total executions, not actions that executed at least once."""
        return sum(history.execution_count for history in self.histories)

    @property
    def attempted(self) -> int:
        """Authorization attempts, which exceeds ``distinct_actions`` under repeats."""
        return sum(len(history.attempts()) for history in self.histories)

    @property
    def distinct_actions(self) -> int:
        """Unique action digests. Repeats of the same action collapse into one."""
        return len(self.histories)

    @property
    def refused_before_compile(self) -> int:
        """Proposals the registry or the scope check refused before a digest existed.

        These have nothing to group by, so they are not in ``histories`` — and their
        absence is the difference between the control path's attempt count and this
        module's. Exposed rather than left as an unexplained gap: a discrepancy an auditor
        has to work out for themselves is a discrepancy they will assume is a bug.
        """
        return sum(
            1 for record in self.orphaned if record.event_type is AuditEventType.ACTION_REFUSED
        )

    @property
    def total_attempts(self) -> int:
        """Every proposal the control path acted on, compiled or not.

        This is the number that should equal the pipeline's own ``attempted``.
        """
        return self.attempted + self.refused_before_compile

    @property
    def sound(self) -> bool:
        """Whether every execution in the trail is justified by the trail."""
        return not self.violations

    def summary(self) -> dict[str, Any]:
        return {
            "distinct_actions": self.distinct_actions,
            "attempts": self.attempted,
            "refused_before_compile": self.refused_before_compile,
            "total_attempts": self.total_attempts,
            "executed": self.executed,
            "violations": [str(violation) for violation in self.violations],
            "sound": self.sound,
        }


def reconstruct(records: Iterable[AuditRecord]) -> Reconstruction:
    """Group a trail by action digest, preserving order within each action."""
    result = Reconstruction()
    index: dict[str, ActionHistory] = {}
    for record in records:
        if not record.action_digest:
            result.orphaned.append(record)
            continue
        history = index.get(record.action_digest)
        if history is None:
            history = ActionHistory(action_digest=record.action_digest)
            index[record.action_digest] = history
            result.histories.append(history)
        history.records.append(record)
    result.violations = list(_violations(result.histories))
    return result


def _violations(histories: Sequence[ActionHistory]) -> Iterable[Violation]:
    """Re-derive authorization for every execution, from the trail alone."""
    for history in histories:
        for attempt in history.attempts():
            yield from _attempt_violations(history, attempt)


def _attempt_violations(
    history: ActionHistory, attempt: Sequence[AuditRecord]
) -> Iterable[Violation]:
    """Check one authorization attempt: every execution in it, against what preceded it."""
    for position, record in enumerate(attempt):
        if record.event_type is not AuditEventType.EXECUTED:
            continue

        # Only events *before* this execution, and within this attempt, can justify it.
        # An approval recorded afterwards is not an authorization, it is a
        # rationalisation — and one recorded during an earlier attempt is not this
        # attempt's.
        prior = attempt[:position]

        if not prior:
            yield Violation(
                history.action_digest,
                "executed with nothing recorded before it; the enforcement path is not "
                "writing to the trail",
                history.tool,
                history.operation,
            )
            continue

        policy = next((r for r in prior if r.event_type is AuditEventType.POLICY_DECIDED), None)
        if policy is None:
            yield Violation(
                history.action_digest,
                "executed with no policy decision recorded",
                history.tool,
                history.operation,
            )
            continue

        outcome = policy.outcome or ""
        if outcome in _CONDITIONAL:
            approval = next(
                (r for r in prior if r.event_type is AuditEventType.APPROVAL_DECIDED), None
            )
            if approval is None:
                yield Violation(
                    history.action_digest,
                    "policy required approval and none was recorded before execution",
                    history.tool,
                    history.operation,
                )
                continue
            if (approval.outcome or "") not in _GRANTED:
                yield Violation(
                    history.action_digest,
                    f"policy required approval and the approval was {approval.outcome!r}",
                    history.tool,
                    history.operation,
                )
                continue
        elif outcome not in _ALLOWING:
            yield Violation(
                history.action_digest,
                f"executed after a policy decision of {outcome!r}",
                history.tool,
                history.operation,
            )
            continue

        if not any(r.event_type is AuditEventType.CAPABILITY_REDEEMED for r in prior):
            yield Violation(
                history.action_digest,
                "executed without redeeming a capability",
                history.tool,
                history.operation,
            )


def format_report(reconstruction: Reconstruction) -> str:
    """A readable replay, for the CLI and the demo."""
    lines = [
        f"{reconstruction.distinct_actions} actions over {reconstruction.attempted} "
        f"attempts, {reconstruction.executed} executed, "
        f"{len(reconstruction.violations)} violations",
        "",
    ]
    for history in reconstruction.histories:
        target = f"{history.tool}.{history.operation}" if history.tool else "?"
        marker = "EXECUTED" if history.executed else "stopped"
        lines.append(f"{history.action_digest[:12]}  {target}  [{marker}]")
        lines.extend(f"    {step}" for step in history.timeline())
    if reconstruction.violations:
        lines += ["", "VIOLATIONS:"]
        lines.extend(f"  - {violation}" for violation in reconstruction.violations)
    else:
        lines += ["", "Every execution in this trail is justified by this trail."]
    return "\n".join(lines)


__all__ = [
    "ActionHistory",
    "Reconstruction",
    "Violation",
    "format_report",
    "reconstruct",
]
