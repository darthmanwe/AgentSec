"""Prometheus metrics, derived from the audit trail (AS-041).

Derived rather than incremented. A counter bumped at each call site is a second
implementation of the control flow, maintained by hand, and it drifts: the day someone
adds an early return, the counter stops matching the behaviour and nothing notices,
because a metric has no test that compares it to reality. Computing the series from the
trail means the metrics and the replay cannot disagree — they read the same input.

The exposition format is written directly rather than pulled from ``prometheus_client``.
It is four lines of formatting against a stable text specification, and the alternative is
a dependency in the runtime path of a project whose entire argument is that its runtime is
small and auditable.

The series that matter are the two the project exists to separate:

* ``agentsec_unauthorized_attempts_total`` — large, and expected to be
* ``agentsec_unauthorized_executions_total`` — the one that must stay at zero

A dashboard showing only the second is a dashboard that looks identical whether the
controls are working or the agent is idle.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentsec.observability.audit import AuditEventType, AuditRecord
from agentsec.observability.replay import reconstruct

#: Stages that mean an action was stopped. Anything not in here and not an execution is
#: an unrecognised outcome, counted separately rather than assumed benign.
_BLOCKED_STAGES: frozenset[str] = frozenset(
    {
        "unknown_tool",
        "invalid_action",
        "out_of_scope",
        "policy_denied",
        "approval_required",
        "approval_denied",
        "gateway_denied",
    }
)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass
class Metric:
    """One Prometheus series family."""

    name: str
    help_text: str
    kind: str = "counter"
    samples: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)

    def add(self, value: float = 1.0, **labels: str) -> None:
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        self.samples[key] = self.samples.get(key, 0.0) + value

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} {self.kind}"]
        if not self.samples:
            # An empty family still exposes a zero. A series that only appears once it is
            # non-zero cannot be alerted on: "no data" and "nothing bad happened" would be
            # the same signal, and they are the two cases most worth telling apart.
            lines.append(f"{self.name} 0")
            return lines
        for key, value in sorted(self.samples.items()):
            if key:
                rendered = ",".join(f'{name}="{_escape(v)}"' for name, v in key)
                lines.append(f"{self.name}{{{rendered}}} {value:g}")
            else:
                lines.append(f"{self.name} {value:g}")
        return lines


@dataclass
class Registry:
    """The metrics a run produces."""

    metrics: list[Metric] = field(default_factory=list)

    def metric(self, name: str, help_text: str, kind: str = "counter") -> Metric:
        for existing in self.metrics:
            if existing.name == name:
                return existing
        created = Metric(name=name, help_text=help_text, kind=kind)
        self.metrics.append(created)
        return created

    def render(self) -> str:
        lines: list[str] = []
        for metric in self.metrics:
            lines.extend(metric.render())
        return "\n".join(lines) + "\n"


def collect(records: Iterable[AuditRecord]) -> Registry:
    """Build the series for one trail."""
    records = list(records)
    registry = Registry()

    attempts = registry.metric(
        "agentsec_unauthorized_attempts_total",
        "Actions proposed that the control path refused. Expected to be large.",
    )
    executions = registry.metric(
        "agentsec_unauthorized_executions_total",
        "Refused actions that reached an external effect anyway. Must be zero.",
    )
    decisions = registry.metric("agentsec_policy_decisions_total", "Policy decisions by outcome.")
    executed = registry.metric(
        "agentsec_executions_total", "Actions that produced an external effect."
    )
    approvals = registry.metric(
        "agentsec_approvals_total", "Approval outcomes, including those never granted."
    )
    capabilities = registry.metric(
        "agentsec_capabilities_total", "Capability grants minted and redeemed."
    )
    violations = registry.metric(
        "agentsec_replay_violations_total",
        "Executions the audit trail cannot justify. The number an auditor reads first.",
    )
    fail_closed = registry.metric(
        "agentsec_policy_fail_closed_total",
        "Decisions made with the policy engine unreachable. A dead engine that denies "
        "everything produces a silently perfect run, so this is surfaced, not hidden.",
    )

    for record in records:
        if record.event_type is AuditEventType.POLICY_DECIDED:
            decisions.add(outcome=str(record.outcome or "unknown"))
            if record.payload.get("fail_closed"):
                fail_closed.add()
        elif record.event_type is AuditEventType.APPROVAL_DECIDED:
            approvals.add(outcome=str(record.outcome or "unknown"))
        elif record.event_type is AuditEventType.APPROVAL_REQUIRED:
            approvals.add(outcome="required")
        elif record.event_type is AuditEventType.CAPABILITY_MINTED:
            capabilities.add(state="minted")
        elif record.event_type is AuditEventType.CAPABILITY_REDEEMED:
            capabilities.add(state="redeemed")
        elif record.event_type is AuditEventType.EXECUTED:
            executed.add(tool=str(record.tool or "unknown"))
        elif record.event_type in (
            AuditEventType.ACTION_REFUSED,
            AuditEventType.DISPATCH_DENIED,
        ):
            stage = str(record.outcome or "unknown")
            attempts.add(stage=stage if stage in _BLOCKED_STAGES else "unrecognised")

    # The headline pair comes from replay rather than from counting events, so the metric
    # and the audit report cannot disagree about the only number that matters.
    reconstruction = reconstruct(records)
    for violation in reconstruction.violations:
        violations.add(tool=str(violation.tool or "unknown"))
        executions.add(tool=str(violation.tool or "unknown"))

    return registry


def render(records: Iterable[AuditRecord]) -> str:
    """The exposition text for a scrape."""
    return collect(records).render()


def summary(records: Iterable[AuditRecord]) -> dict[str, Any]:
    """The same numbers, for a log line or an artifact."""
    records = list(records)
    reconstruction = reconstruct(records)
    return {
        "actions": reconstruction.attempted,
        "executed": reconstruction.executed,
        "violations": len(reconstruction.violations),
        "events": len(records),
    }


__all__ = ["Metric", "Registry", "collect", "render", "summary"]
