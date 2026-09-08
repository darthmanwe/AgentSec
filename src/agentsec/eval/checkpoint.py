"""Crash-safe run state and resume (AS-040 hardening).

A funded run writes its results **as it goes**, not at the end. The version that
accumulates cells in memory and serialises once is fine until something kills the process
at 90%, at which point the money is spent and the artifact does not exist.

So a run is a directory:

    eval/runs/<run-id>/
        run.json          settings, preregistration lock, status
        cells/<cell>.json one file per completed cell, written the moment it finishes
        cache/            paid-for responses (see cache.py)
        events.jsonl      append-only progress log

**Resume is the point.** ``--resume <run-id>`` reads the cell files that exist, skips those
cells, and continues. Combined with the response cache, a resumed run re-buys nothing: the
cells that completed are already on disk, and any partially-completed cell replays its
model calls for free.

**Every write is atomic** — temp file plus ``os.replace``. A half-written cell file would
turn a recoverable crash into an unrecoverable one, which is the single failure this module
must not cause itself.

The status field is explicit and terminal states are distinguishable. ``interrupted`` is
not ``failed`` and neither is ``completed``; a reader has to be able to tell "the operator
stopped it", "it broke", and "it finished" apart, because only the last one produces a
number anybody should quote.
"""

from __future__ import annotations

import datetime as dt
import enum
import json
import os
import pathlib
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Any, Final

from agentsec.log import get_logger

log = get_logger("agentsec.eval.checkpoint")

RUNS_DIR: Final = pathlib.Path(__file__).resolve().parents[3] / "eval" / "runs"


class RunStatus(enum.StrEnum):
    """How a run ended.

    Distinguished rather than collapsed into a boolean. "The operator stopped it", "it
    broke", "the budget ran out" and "it finished" are four different things, and only the
    last produces a number worth quoting.
    """

    RUNNING = "running"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    DEADLINE_REACHED = "deadline_reached"

    @property
    def is_terminal(self) -> bool:
        return self is not RunStatus.RUNNING

    @property
    def is_complete(self) -> bool:
        """Whether every planned cell finished. Only then is the run reportable."""
        return self is RunStatus.COMPLETED


def new_run_id(prefix: str = "run") -> str:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6]}"


def write_atomic(path: pathlib.Path, document: dict[str, Any]) -> None:
    """Write JSON via a temp file and an atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # delete=False and a manual replace, because the file has to outlive the handle: the
    # whole point is to rename it into place. A context manager cannot express that, which
    # is why SIM115 is suppressed here rather than worked around.
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=path.parent,
        prefix=f".{path.stem}.",
        suffix=".tmp",
        delete=False,
    )
    temporary = pathlib.Path(handle.name)
    try:
        with handle as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            # fsync before the rename. Without it the rename can be durable while the
            # contents are not, which on a crash leaves an empty file where a cached
            # response used to be - the exact loss this function exists to prevent.
            os.fsync(stream.fileno())
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@dataclass
class RunDirectory:
    """The on-disk state of one run."""

    run_id: str
    root: pathlib.Path
    status: RunStatus = RunStatus.RUNNING
    planned_cells: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        run_id: str | None = None,
        base: pathlib.Path = RUNS_DIR,
        planned_cells: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> RunDirectory:
        identifier = run_id or new_run_id()
        root = base / identifier
        (root / "cells").mkdir(parents=True, exist_ok=True)
        (root / "cache").mkdir(parents=True, exist_ok=True)
        directory = cls(
            run_id=identifier,
            root=root,
            planned_cells=planned_cells,
            metadata=dict(metadata or {}),
        )
        directory.save()
        return directory

    @classmethod
    def open(cls, run_id: str, *, base: pathlib.Path = RUNS_DIR) -> RunDirectory:
        """Reopen an existing run for resume.

        Refuses a run that already completed. Resuming a finished run would append to a
        result that has already been reported, and the second version would not match the
        artifact somebody quoted.
        """
        root = base / run_id
        manifest = root / "run.json"
        if not manifest.exists():
            raise FileNotFoundError(f"no run at {root}")

        document = json.loads(manifest.read_text(encoding="utf-8"))
        status = RunStatus(document.get("status", RunStatus.RUNNING.value))
        if status.is_complete:
            raise ValueError(
                f"run {run_id} already completed; resuming it would append to a result "
                "that has already been reported"
            )
        return cls(
            run_id=run_id,
            root=root,
            status=RunStatus.RUNNING,
            planned_cells=tuple(document.get("planned_cells", ())),
            metadata=dict(document.get("metadata", {})),
        )

    # ------------------------------------------------------------------ paths

    @property
    def cells_dir(self) -> pathlib.Path:
        return self.root / "cells"

    @property
    def cache_dir(self) -> pathlib.Path:
        return self.root / "cache"

    @property
    def events_path(self) -> pathlib.Path:
        return self.root / "events.jsonl"

    # ------------------------------------------------------------------ cells

    @staticmethod
    def _cell_file(cell: str) -> str:
        return cell.replace("/", "__") + ".json"

    def completed_cells(self) -> set[str]:
        """Which cells already have results on disk.

        Read from the filesystem rather than from a manifest the process maintains. A
        manifest can disagree with reality after a crash; the files cannot.
        """
        found: set[str] = set()
        for path in self.cells_dir.glob("*.json"):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                # A corrupt cell file means that cell did not finish cleanly. Removing it
                # so the resume re-runs it is correct: the model calls it made are in the
                # cache, so re-running costs nothing.
                log.warning("discarding a corrupt cell result", path=str(path))
                path.unlink(missing_ok=True)
                continue
            if document.get("complete") is True:
                found.add(str(document.get("cell", path.stem)))
        return found

    def save_cell(self, cell: str, document: dict[str, Any], *, complete: bool = True) -> None:
        """Persist one cell's results immediately.

        ``complete`` is stored explicitly so a partial cell can be written for diagnosis
        without a resume mistaking it for finished work.
        """
        payload = {**document, "cell": cell, "complete": complete}
        write_atomic(self.cells_dir / self._cell_file(cell), payload)
        self.append_event({"event": "cell_saved", "cell": cell, "complete": complete})

    def load_cells(self) -> list[dict[str, Any]]:
        """Every cell result on disk, in a stable order."""
        results: list[dict[str, Any]] = []
        for path in sorted(self.cells_dir.glob("*.json")):
            try:
                results.append(json.loads(path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                continue
        return results

    # ------------------------------------------------------------------ progress

    def append_audit(self, records: Any) -> None:
        """Persist a cell's audit trail as JSON Lines.

        Kept separate from ``events.jsonl``, which is progress reporting, because this file
        is *evidence*: it is what ``agentsec-replay`` reads to check the invariant without
        the code that enforced it. Held only in memory, the trail would exist for the
        duration of a cell and then be summarised into a number nobody could re-derive.
        """
        path = self.root / "audit.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record.as_row(), sort_keys=True) + "\n")

    def append_event(self, event: dict[str, Any]) -> None:
        """Append to the progress log.

        Append-only JSONL, flushed on every line. A run that dies leaves a readable
        history of how far it got, which is the difference between "it failed" and "it
        failed after cell seven, during the approval arm".
        """
        record = {"at": dt.datetime.now(dt.UTC).isoformat(), **event}
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()

    def set_status(self, status: RunStatus, detail: str = "") -> None:
        self.status = status
        self.metadata["status_detail"] = detail
        self.save()
        self.append_event({"event": "status", "status": status.value, "detail": detail})

    def save(self) -> None:
        write_atomic(
            self.root / "run.json",
            {
                "run_id": self.run_id,
                "status": self.status.value,
                "planned_cells": list(self.planned_cells),
                "completed_cells": sorted(self.completed_cells()),
                "metadata": self.metadata,
                "updated_at": dt.datetime.now(dt.UTC).isoformat(),
            },
        )

    # ------------------------------------------------------------------ reporting

    @property
    def remaining_cells(self) -> tuple[str, ...]:
        done = self.completed_cells()
        return tuple(cell for cell in self.planned_cells if cell not in done)

    def progress(self) -> dict[str, Any]:
        done = len(self.completed_cells())
        planned = len(self.planned_cells)
        return {
            "run_id": self.run_id,
            "status": self.status.value,
            "cells_completed": done,
            "cells_planned": planned,
            "fraction": (done / planned) if planned else None,
            "remaining": list(self.remaining_cells),
        }


def list_runs(base: pathlib.Path = RUNS_DIR) -> list[dict[str, Any]]:
    """Every run on disk, newest first. Used by ``--list-runs`` to find a run to resume."""
    if not base.exists():
        return []
    found: list[dict[str, Any]] = []
    for path in sorted(base.iterdir(), reverse=True):
        manifest = path / "run.json"
        if not manifest.exists():
            continue
        try:
            found.append(json.loads(manifest.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return found


__all__ = [
    "RUNS_DIR",
    "RunDirectory",
    "RunStatus",
    "list_runs",
    "new_run_id",
    "write_atomic",
]
