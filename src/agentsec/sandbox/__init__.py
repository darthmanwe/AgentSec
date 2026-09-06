"""Ephemeral container isolation for untrusted work (AS-031A).

Built before any scanner exists, so no scanner is ever exercised on the host. See
:mod:`agentsec.sandbox.runner` for the two rules that are absolute rather than
configurable: no host bind mounts, and no Docker socket.
"""

from agentsec.sandbox.reaper import ReapReport, find_leftovers, reap
from agentsec.sandbox.runner import (
    LABEL,
    NOBODY,
    RUN_LABEL,
    SCRATCH,
    WORKSPACE,
    DockerSandbox,
    DockerUnavailableError,
    SandboxError,
    SandboxLimits,
    SandboxResult,
    Workspace,
    docker_available,
    require_volume_name,
)

__all__ = [
    "LABEL",
    "NOBODY",
    "RUN_LABEL",
    "SCRATCH",
    "WORKSPACE",
    "DockerSandbox",
    "DockerUnavailableError",
    "ReapReport",
    "SandboxError",
    "SandboxLimits",
    "SandboxResult",
    "Workspace",
    "docker_available",
    "find_leftovers",
    "reap",
    "require_volume_name",
]
