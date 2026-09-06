"""Fault harness unit tests (AS-023).

The harness decides which failures happen, so a bug in it produces durability tests that
pass by breaking nothing. These run without Docker and check the selection logic and the
recovery report before anything is wired to a real worker — the same reason the import
boundary and determinism scanners are tested against synthetic input first.
"""

from __future__ import annotations

import json

import pytest

from agentsec.faults import (
    ANY_ACTIVITY,
    Fault,
    FaultInjector,
    FaultKind,
    RecoveryReport,
    denial,
    duplicate,
    hang,
    malformed,
    plan,
    transient,
)

pytestmark = pytest.mark.authz


# --------------------------------------------------------------------------- selection


def test_a_fault_fires_only_on_its_scheduled_attempt() -> None:
    """Scheduled, not random. A fault that fires on an unpredictable attempt makes the
    recovery assertion unpredictable too, and an unpredictable gate gets switched off."""
    injector = plan(transient("collect_context", attempts=(1, 2)))

    assert injector.select("collect_context", 1) is not None
    assert injector.select("collect_context", 2) is not None
    assert injector.select("collect_context", 3) is None


def test_a_fault_is_scoped_to_its_activity() -> None:
    injector = plan(transient("collect_context"))
    assert injector.select("plan_actions", 1) is None


def test_a_wildcard_targets_every_activity() -> None:
    injector = plan(Fault(activity=ANY_ACTIVITY, kind=FaultKind.TIMEOUT))
    assert injector.select("anything_at_all", 1) is not None


def test_a_specific_fault_beats_a_wildcard() -> None:
    """Otherwise a broad timeout sweep would silently swallow the one targeted fault a
    test was actually asserting on."""
    injector = plan(
        Fault(activity=ANY_ACTIVITY, kind=FaultKind.TIMEOUT),
        transient("plan_actions"),
    )
    selected = injector.select("plan_actions", 1)
    assert selected is not None
    assert selected.kind is FaultKind.TRANSIENT_ERROR


def test_an_empty_plan_breaks_nothing() -> None:
    assert FaultInjector().select("collect_context", 1) is None


@pytest.mark.parametrize(
    ("factory", "kind"),
    [
        (transient, FaultKind.TRANSIENT_ERROR),
        (denial, FaultKind.NON_RETRYABLE),
        (duplicate, FaultKind.DUPLICATE_EXECUTION),
        (malformed, FaultKind.MALFORMED_RESULT),
        (hang, FaultKind.TIMEOUT),
    ],
)
def test_every_builder_produces_its_kind(factory: object, kind: FaultKind) -> None:
    assert factory("some_activity").kind is kind  # type: ignore[operator]


# --------------------------------------------------------------------------- reporting


def test_the_report_refuses_a_run_where_nothing_broke() -> None:
    """The failure mode that matters most here.

    A plan targeting a renamed activity matches nothing, every durability test passes
    against an unbroken system, and the suite is green while proving nothing at all.
    """
    with pytest.raises(AssertionError, match="matched nothing"):
        RecoveryReport().assert_fired()


def test_the_report_checks_how_many_faults_fired() -> None:
    injector = plan(transient("a"), transient("b"))
    injector.record_injection(injector.faults[0], "a", 1)

    injector.report.assert_fired(1)
    with pytest.raises(AssertionError, match="expected 2"):
        injector.report.assert_fired(2)


def test_the_report_marks_a_multi_attempt_completion_as_recovered() -> None:
    injector = FaultInjector()
    injector.record_completion("collect_context", 3)
    injector.record_completion("plan_actions", 1)

    assert injector.report.summary()["recovered_activities"] == ["collect_context"]
    assert injector.report.attempts_for("collect_context") == 3


def test_the_report_serialises() -> None:
    """It is an artifact, so it has to survive JSON. The dataclasses are slotted and have
    no ``__dict__``, which is the obvious way to write this and does not work."""
    injector = plan(transient("collect_context"))
    injector.record_injection(injector.faults[0], "collect_context", 1)
    injector.record_completion("collect_context", 2)

    document = json.loads(injector.report.to_json())
    assert document["summary"]["induced_failures"] == 1
    assert document["summary"]["by_kind"]["transient_error"] == 1
    assert document["induced"][0]["activity"] == "collect_context"
    assert document["completions"][0]["recovered"] is True


def test_the_report_counts_every_kind_even_at_zero() -> None:
    """A summary that omits absent kinds makes two runs hard to diff, and comparing runs
    is the entire use of this artifact."""
    by_kind = FaultInjector().report.summary()["by_kind"]
    assert set(by_kind) == {kind.value for kind in FaultKind}
