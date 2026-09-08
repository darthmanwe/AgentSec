"""Replay an audit trail from the command line (AS-041).

An audit trail nobody can read is a table. This turns one into the two things a reviewer
actually asks for: a timeline of what happened to each action, and a verdict on whether
any execution went unjustified.

Reads JSON Lines, which is what the evaluation's ``events.jsonl`` already is and what a
database export can trivially become. Deliberately not a database client: the point of
replay is that it needs nothing but the record.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any

from agentsec.observability.audit import AuditEventType, AuditRecord
from agentsec.observability.metrics import render as render_metrics
from agentsec.observability.replay import format_report, reconstruct


def parse_record(document: dict[str, Any]) -> AuditRecord | None:
    """Build a record from one JSON object, or ``None`` if it is not an audit event.

    Returning ``None`` rather than raising is deliberate: a trail file is append-only and
    may hold other things — the evaluation's ``events.jsonl`` interleaves run progress with
    everything else. Refusing the whole file over one foreign line would make replay
    unusable on real data.
    """
    raw_type = document.get("event_type") or document.get("event")
    if not isinstance(raw_type, str):
        return None
    try:
        event_type = AuditEventType(raw_type)
    except ValueError:
        return None

    occurred = document.get("occurred_at") or document.get("timestamp")
    try:
        stamp = dt.datetime.fromisoformat(str(occurred).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        stamp = dt.datetime.now(dt.UTC)

    return AuditRecord(
        event_type=event_type,
        occurred_at=stamp,
        run_id=document.get("run_id"),
        workflow_id=document.get("workflow_id"),
        action_digest=document.get("action_digest"),
        principal=document.get("principal"),
        tool=document.get("tool"),
        operation=document.get("operation"),
        outcome=document.get("outcome"),
        reason=document.get("reason"),
        payload=document.get("payload") or {},
    )


def load(path: pathlib.Path) -> list[AuditRecord]:
    records: list[AuditRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(document, dict):
            parsed = parse_record(document)
            if parsed is not None:
                records.append(parsed)
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentsec-replay",
        description="Reconstruct a run from its audit trail and check the invariant.",
    )
    parser.add_argument("trail", help="JSON Lines file of audit events")
    parser.add_argument(
        "--metrics", action="store_true", help="emit Prometheus exposition instead of a report"
    )
    parser.add_argument("--json", action="store_true", help="emit the summary as JSON")
    arguments = parser.parse_args(argv)

    path = pathlib.Path(arguments.trail)
    if not path.is_file():
        print(f"error: {path} does not exist", file=sys.stderr)  # noqa: T201
        return 2

    records = load(path)
    if not records:
        # Not success. An empty trail is the shape an enforcement path that stopped
        # writing produces, and reporting "0 violations" over it would be exactly the
        # false assurance this module exists to refuse.
        print(f"error: no audit events found in {path}", file=sys.stderr)  # noqa: T201
        return 2

    reconstruction = reconstruct(records)
    if arguments.metrics:
        print(render_metrics(records), end="")  # noqa: T201
    elif arguments.json:
        print(json.dumps(reconstruction.summary(), indent=2))  # noqa: T201
    else:
        print(format_report(reconstruction))  # noqa: T201

    return 0 if reconstruction.sound else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
