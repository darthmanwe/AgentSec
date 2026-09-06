"""Reclaim sandbox leftovers (AS-031A).

The runner removes its volume in a ``finally`` block, which covers every exit it gets to
observe. It does not cover the ones it does not: a killed process, a machine that lost
power, a Docker daemon restart mid-run. Those leave a labelled volume behind.

That matters more here than tidiness usually does. Docker Desktop's disk image only ever
grows — reclaiming space inside it does not shrink the file on the host — so leaked
workspaces accumulate permanently on a laptop that also holds a OneDrive-synced working
tree. And a leaked volume holds whatever the run was doing when it died, which for this
project means attacker-authored source.

Everything is found by label, never by name pattern. A name-matching reaper deletes
somebody else's volume the day a naming convention changes.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from agentsec.log import get_logger
from agentsec.sandbox.runner import LABEL, RUN_LABEL

log = get_logger("agentsec.sandbox.reaper")


@dataclass(frozen=True, slots=True)
class ReapReport:
    """What was reclaimed. Returned rather than logged so a caller can assert on it."""

    volumes: tuple[str, ...] = ()
    containers: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.volumes) + len(self.containers)


def _docker(args: list[str], docker: str = "docker") -> list[str]:
    result = subprocess.run(  # noqa: S603
        [docker, *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        log.warning("docker command failed", args=args, stderr=result.stderr.strip())
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def find_leftovers(*, run_id: str | None = None, docker: str = "docker") -> ReapReport:
    """List sandbox volumes and containers still present, without removing anything."""
    label = f"{RUN_LABEL}={run_id}" if run_id else f"{LABEL}=true"
    volumes = _docker(["volume", "ls", "--filter", f"label={label}", "--quiet"], docker)
    containers = _docker(
        ["ps", "--all", "--filter", f"label={label}", "--quiet", "--no-trunc"], docker
    )
    return ReapReport(volumes=tuple(volumes), containers=tuple(containers))


def reap(*, run_id: str | None = None, docker: str = "docker") -> ReapReport:
    """Remove sandbox leftovers.

    Containers first: a volume still attached to one cannot be removed, and reversing the
    order produces a reaper that reports success while reclaiming nothing.
    """
    found = find_leftovers(run_id=run_id, docker=docker)

    for container in found.containers:
        _docker(["rm", "--force", container], docker)
    for volume in found.volumes:
        _docker(["volume", "rm", "--force", volume], docker)

    if found.total:
        log.info(
            "reaped sandbox leftovers",
            volumes=len(found.volumes),
            containers=len(found.containers),
            run_id=run_id,
        )
    return found


__all__ = ["ReapReport", "find_leftovers", "reap"]
