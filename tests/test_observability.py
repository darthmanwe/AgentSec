"""Audit trail and replay (AS-041).

The tests that matter here are the ones where replay *disagrees* with the pipeline. A
replay that only ever confirms what the enforcement layer already said is a second opinion
from the same author, and worth nothing.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib

import pytest

from agentsec.observability import cli, metrics
from agentsec.observability.audit import (
    AuditEventType,
    AuditRecord,
    AuditTrail,
    LoggingAuditSink,
    MemoryAuditSink,
    NullAuditSink,
)
from agentsec.observability.replay import format_report, reconstruct

pytestmark = pytest.mark.authz

DIGEST = "a" * 64
OTHER = "b" * 64


def record(
    event_type: AuditEventType,
    *,
    digest: str = DIGEST,
    outcome: str | None = None,
    offset: int = 0,
) -> AuditRecord:
    return AuditRecord(
        event_type=event_type,
        occurred_at=dt.datetime(2026, 9, 8, 12, 0, offset, tzinfo=dt.UTC),
        action_digest=digest,
        tool="fake_jira",
        operation="create_issue",
        outcome=outcome,
    )


def authorized_chain(policy_outcome: str = "ALLOW") -> list[AuditRecord]:
    chain = [
        record(AuditEventType.ACTION_COMPILED, offset=1),
        record(AuditEventType.POLICY_DECIDED, outcome=policy_outcome, offset=2),
    ]
    if policy_outcome == "REQUIRE_APPROVAL":
        chain.append(record(AuditEventType.APPROVAL_DECIDED, outcome="granted", offset=3))
    chain += [
        record(AuditEventType.CAPABILITY_MINTED, outcome="minted", offset=4),
        record(AuditEventType.CAPABILITY_REDEEMED, outcome="redeemed", offset=5),
        record(AuditEventType.EXECUTED, outcome="executed", offset=6),
    ]
    return chain


# --------------------------------------------------------------------------- the sinks


def test_the_default_sink_records_nothing() -> None:
    """Auditing is opt-in, so a caller who forgot a sink gets no trail, not a crash."""
    trail = AuditTrail(None, run_id="r")
    assert trail.emit(AuditEventType.PLAN_PROPOSED) is not None


def test_records_arrive_in_order() -> None:
    sink = MemoryAuditSink()
    trail = AuditTrail(sink, run_id="r")
    trail.emit(AuditEventType.PLAN_PROPOSED)
    trail.emit(AuditEventType.ACTION_COMPILED, action_digest=DIGEST)
    assert [r.event_type for r in sink.records] == [
        AuditEventType.PLAN_PROPOSED,
        AuditEventType.ACTION_COMPILED,
    ]


def test_the_payload_is_redacted() -> None:
    """The trail records arguments by design, which is exactly where a secret ends up."""
    sink = MemoryAuditSink()
    AuditTrail(sink).emit(AuditEventType.ACTION_COMPILED, api_key="sk-ant-secret-value")
    assert "sk-ant-secret-value" not in str(sink.records[0].payload)


def test_the_logging_sink_does_not_raise() -> None:
    AuditTrail(LoggingAuditSink()).emit(AuditEventType.EXECUTED, action_digest=DIGEST)


def test_the_null_sink_discards() -> None:
    sink = NullAuditSink()
    assert sink.emit(record(AuditEventType.EXECUTED)) is None


# --------------------------------------------------------------------------- reconstruction


def test_actions_are_grouped_by_digest() -> None:
    reconstruction = reconstruct(
        [
            record(AuditEventType.ACTION_COMPILED, digest=DIGEST),
            record(AuditEventType.ACTION_COMPILED, digest=OTHER),
            record(AuditEventType.POLICY_DECIDED, digest=DIGEST, outcome="DENY"),
        ]
    )
    assert reconstruction.attempted == 2
    assert len(reconstruction.histories[0].records) == 2


def test_events_without_a_digest_are_kept_not_dropped() -> None:
    """Plan-level events have no digest and still belong to the run."""
    reconstruction = reconstruct(
        [AuditRecord(event_type=AuditEventType.PLAN_PROPOSED, occurred_at=dt.datetime.now(dt.UTC))]
    )
    assert len(reconstruction.orphaned) == 1
    assert reconstruction.attempted == 0


# --------------------------------------------------------------------------- soundness


def test_a_fully_authorized_execution_is_sound() -> None:
    reconstruction = reconstruct(authorized_chain())
    assert reconstruction.sound
    assert reconstruction.executed == 1


def test_an_approved_execution_is_sound() -> None:
    reconstruction = reconstruct(authorized_chain("REQUIRE_APPROVAL"))
    assert reconstruction.sound


def test_a_blocked_action_is_sound_because_nothing_executed() -> None:
    reconstruction = reconstruct(
        [
            record(AuditEventType.ACTION_COMPILED),
            record(AuditEventType.POLICY_DECIDED, outcome="DENY"),
            record(AuditEventType.DISPATCH_DENIED, outcome="policy_denied"),
        ]
    )
    assert reconstruction.sound
    assert reconstruction.executed == 0


# --------------------------------------------------------------------------- violations


def test_execution_after_a_denial_is_a_violation() -> None:
    """The case the whole module exists for.

    If the pipeline ever executes something policy denied, the trail says so even though
    the pipeline believed it was fine.
    """
    chain = authorized_chain()
    chain[1] = record(AuditEventType.POLICY_DECIDED, outcome="DENY", offset=2)
    reconstruction = reconstruct(chain)
    assert not reconstruction.sound
    assert "DENY" in str(reconstruction.violations[0])


def test_execution_with_no_policy_decision_is_a_violation() -> None:
    chain = [
        step for step in authorized_chain() if step.event_type is not AuditEventType.POLICY_DECIDED
    ]
    reconstruction = reconstruct(chain)
    assert not reconstruction.sound
    assert "no policy decision" in str(reconstruction.violations[0])


def test_execution_without_redeeming_a_capability_is_a_violation() -> None:
    chain = [
        step
        for step in authorized_chain()
        if step.event_type is not AuditEventType.CAPABILITY_REDEEMED
    ]
    reconstruction = reconstruct(chain)
    assert not reconstruction.sound
    assert "without redeeming a capability" in str(reconstruction.violations[0])


def test_a_required_approval_that_never_arrived_is_a_violation() -> None:
    chain = [
        step
        for step in authorized_chain("REQUIRE_APPROVAL")
        if step.event_type is not AuditEventType.APPROVAL_DECIDED
    ]
    reconstruction = reconstruct(chain)
    assert not reconstruction.sound
    assert "none was recorded" in str(reconstruction.violations[0])


def test_a_denied_approval_followed_by_execution_is_a_violation() -> None:
    chain = authorized_chain("REQUIRE_APPROVAL")
    chain[2] = record(AuditEventType.APPROVAL_DECIDED, outcome="denied", offset=3)
    reconstruction = reconstruct(chain)
    assert not reconstruction.sound


def test_an_approval_recorded_after_the_execution_does_not_justify_it() -> None:
    """An authorization that arrives late is not an authorization.

    This is the ordering check, and it is the one that catches an approval gate wired in
    the wrong sequence — where every required event exists and the run is still wrong.
    """
    chain = [
        record(AuditEventType.ACTION_COMPILED, offset=1),
        record(AuditEventType.POLICY_DECIDED, outcome="REQUIRE_APPROVAL", offset=2),
        record(AuditEventType.CAPABILITY_REDEEMED, outcome="redeemed", offset=3),
        record(AuditEventType.EXECUTED, outcome="executed", offset=4),
        record(AuditEventType.APPROVAL_DECIDED, outcome="granted", offset=5),
    ]
    reconstruction = reconstruct(chain)
    assert not reconstruction.sound


def test_a_bare_execution_is_a_violation_not_a_clean_run() -> None:
    """Silence must not read as success.

    An enforcement path that stopped writing to the trail produces exactly this shape, and
    it is the most dangerous thing a trail can contain.
    """
    reconstruction = reconstruct([record(AuditEventType.EXECUTED, outcome="executed")])
    assert not reconstruction.sound
    assert "not writing to the trail" in str(reconstruction.violations[0])


def test_one_bad_action_among_good_ones_is_still_caught() -> None:
    chain = authorized_chain()
    rogue = [
        AuditRecord(
            event_type=AuditEventType.EXECUTED,
            occurred_at=dt.datetime.now(dt.UTC),
            action_digest=OTHER,
            tool="github",
            operation="comment_pull_request",
            outcome="executed",
        )
    ]
    reconstruction = reconstruct(chain + rogue)
    assert reconstruction.executed == 2
    assert len(reconstruction.violations) == 1
    assert "github" in str(reconstruction.violations[0])


# --------------------------------------------------------------------------- reporting


def test_the_report_names_the_violation() -> None:
    chain = authorized_chain()
    chain[1] = record(AuditEventType.POLICY_DECIDED, outcome="DENY", offset=2)
    text = format_report(reconstruct(chain))
    assert "VIOLATIONS" in text


def test_a_clean_report_says_what_it_checked() -> None:
    text = format_report(reconstruct(authorized_chain()))
    assert "justified by this trail" in text


def test_the_summary_is_serialisable() -> None:
    summary = reconstruct(authorized_chain()).summary()
    assert summary["sound"] is True
    assert summary["executed"] == 1


# --------------------------------------------------------------------------- metrics


def test_the_two_headline_series_are_always_present() -> None:
    """A series that only appears once it is non-zero cannot be alerted on.

    "No data" and "nothing bad happened" would be the same signal, and they are the two
    cases most worth telling apart.
    """
    text = metrics.render([])
    assert "agentsec_unauthorized_attempts_total 0" in text
    assert "agentsec_unauthorized_executions_total 0" in text


def test_blocked_actions_count_as_attempts() -> None:
    text = metrics.render(
        [
            record(AuditEventType.DISPATCH_DENIED, outcome="policy_denied"),
            record(AuditEventType.ACTION_REFUSED, outcome="out_of_scope", digest=OTHER),
        ]
    )
    assert 'agentsec_unauthorized_attempts_total{stage="policy_denied"} 1' in text
    assert 'agentsec_unauthorized_attempts_total{stage="out_of_scope"} 1' in text


def test_an_unrecognised_stage_is_labelled_not_ignored() -> None:
    """An outcome nobody anticipated must not silently vanish from the numbers."""
    text = metrics.render([record(AuditEventType.DISPATCH_DENIED, outcome="something_new")])
    assert 'stage="unrecognised"' in text


def test_unauthorized_executions_come_from_replay_not_from_counting() -> None:
    """The metric and the audit report read the same input, so they cannot disagree."""
    chain = authorized_chain()
    chain[1] = record(AuditEventType.POLICY_DECIDED, outcome="DENY", offset=2)
    text = metrics.render(chain)
    assert "agentsec_unauthorized_executions_total{" in text
    assert "agentsec_replay_violations_total{" in text


def test_a_sound_run_reports_zero_unauthorized_executions() -> None:
    text = metrics.render(authorized_chain())
    assert "agentsec_unauthorized_executions_total 0" in text
    assert 'agentsec_executions_total{tool="fake_jira"} 1' in text


def test_a_fail_closed_decision_is_surfaced() -> None:
    """A dead policy engine denies everything and produces a perfect-looking run."""
    trail = MemoryAuditSink()
    AuditTrail(trail).emit(
        AuditEventType.POLICY_DECIDED, action_digest=DIGEST, outcome="DENY", fail_closed=True
    )
    assert "agentsec_policy_fail_closed_total 1" in metrics.render(trail.records)


def test_label_values_are_escaped() -> None:
    quoted = AuditRecord(
        event_type=AuditEventType.EXECUTED,
        occurred_at=dt.datetime.now(dt.UTC),
        action_digest=DIGEST,
        tool='we"ird\tool',
        outcome="executed",
    )
    assert '\\"' in metrics.render([quoted])


def test_the_summary_agrees_with_replay() -> None:
    chain = authorized_chain()
    assert metrics.summary(chain)["executed"] == reconstruct(chain).executed


# --------------------------------------------------------------------------- repeats


def test_a_repeated_action_is_checked_once_per_attempt() -> None:
    """The same action proposed twice produces the same digest, by design.

    So one history can hold several complete attempts. Checking only the first execution
    would let every later one through unexamined — which is exactly what the evaluation
    does 3 times per case.
    """
    reconstruction = reconstruct(authorized_chain() + authorized_chain())
    assert reconstruction.distinct_actions == 1
    assert reconstruction.attempted == 2
    assert reconstruction.executed == 2
    assert reconstruction.sound


def test_an_earlier_approval_does_not_justify_a_later_execution() -> None:
    """The subtle one, and the reason attempts are segmented rather than concatenated.

    Attempt 1 is properly approved. Attempt 2 executes with no approval of its own. Read
    as one flat list, attempt 1's approval sits before attempt 2's execution and appears
    to authorize it.
    """
    first = authorized_chain("REQUIRE_APPROVAL")
    second = [
        record(AuditEventType.ACTION_COMPILED, offset=10),
        record(AuditEventType.POLICY_DECIDED, outcome="REQUIRE_APPROVAL", offset=11),
        record(AuditEventType.CAPABILITY_REDEEMED, outcome="redeemed", offset=12),
        record(AuditEventType.EXECUTED, outcome="executed", offset=13),
    ]
    reconstruction = reconstruct(first + second)
    assert not reconstruction.sound
    assert "none was recorded" in str(reconstruction.violations[0])


def test_a_second_execution_in_one_attempt_is_still_checked() -> None:
    chain = authorized_chain()
    chain.append(record(AuditEventType.EXECUTED, outcome="executed", offset=7))
    reconstruction = reconstruct(chain)
    assert reconstruction.executed == 2
    assert reconstruction.sound


def test_refusals_before_a_digest_are_accounted_for() -> None:
    """A proposal refused by the registry never gets a digest, so it has no history.

    Its absence is the whole difference between the pipeline's attempt count and replay's.
    Left unexplained it reads as a bug in one of them.
    """
    reconstruction = reconstruct(
        [
            *authorized_chain(),
            AuditRecord(
                event_type=AuditEventType.ACTION_REFUSED,
                occurred_at=dt.datetime.now(dt.UTC),
                tool="nonexistent",
                operation="whatever",
                outcome="unknown_tool",
            ),
        ]
    )
    assert reconstruction.attempted == 1
    assert reconstruction.refused_before_compile == 1
    assert reconstruction.total_attempts == 2


# --------------------------------------------------------------------------- the CLI


def test_the_cli_replays_a_trail(tmp_path: pathlib.Path) -> None:
    trail = tmp_path / "trail.jsonl"
    trail.write_text(
        "\n".join(json.dumps(r.as_row()) for r in authorized_chain()), encoding="utf-8"
    )
    assert cli.main([str(trail)]) == 0


def test_the_cli_exits_non_zero_on_a_violation(tmp_path: pathlib.Path) -> None:
    """So it can gate a pipeline rather than only inform one."""
    chain = authorized_chain()
    chain[1] = record(AuditEventType.POLICY_DECIDED, outcome="DENY", offset=2)
    trail = tmp_path / "trail.jsonl"
    trail.write_text("\n".join(json.dumps(r.as_row()) for r in chain), encoding="utf-8")
    assert cli.main([str(trail)]) == 1


def test_an_empty_trail_is_an_error_not_a_clean_run(tmp_path: pathlib.Path) -> None:
    """The shape an enforcement path that stopped writing produces.

    Reporting "0 violations" over it would be precisely the false assurance replay exists
    to refuse.
    """
    trail = tmp_path / "trail.jsonl"
    trail.write_text("", encoding="utf-8")
    assert cli.main([str(trail)]) == 2


def test_foreign_lines_are_skipped_not_fatal(tmp_path: pathlib.Path) -> None:
    """Real trail files interleave other events; refusing the file would make replay
    unusable on the evaluation's own events.jsonl."""
    trail = tmp_path / "trail.jsonl"
    lines = [json.dumps({"event": "cell_started", "cell": "x"}), "not json at all", ""]
    lines += [json.dumps(r.as_row()) for r in authorized_chain()]
    trail.write_text("\n".join(lines), encoding="utf-8")
    assert cli.main([str(trail)]) == 0


def test_a_missing_file_is_an_error(tmp_path: pathlib.Path) -> None:
    assert cli.main([str(tmp_path / "nope.jsonl")]) == 2


def test_the_cli_can_emit_metrics(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    trail = tmp_path / "trail.jsonl"
    trail.write_text(
        "\n".join(json.dumps(r.as_row()) for r in authorized_chain()), encoding="utf-8"
    )
    cli.main([str(trail), "--metrics"])
    assert "agentsec_unauthorized_executions_total" in capsys.readouterr().out
