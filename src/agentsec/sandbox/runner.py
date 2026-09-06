"""Ephemeral Docker sandbox (AS-031A).

Built **before** any scanner exists, so no scanner is ever exercised on the host. The
ordering is the point: with the sandbox second, the adapters get written and debugged
against a host install, acquire habits that only work there, and the isolation boundary
arrives to find code shaped around its absence. On this host it is not even possible —
neither Semgrep nor Trivy has a supported native Windows install.

What runs inside is untrusted twice over: a scanner processing attacker-authored source,
and, later, tool output the planner asked for. The container gets no network, no
capabilities, no writable root, no privilege escalation, and a bounded slice of CPU,
memory, processes and wall clock.

Two rules that are absolute rather than configurable:

**Never bind-mount a host path.** Workspaces stage into a per-run Docker volume over a tar
stream. Bind-mounting the repository would hand a compromised scanner the working tree,
and on this host it would also hand it a OneDrive-synced folder. There is no flag to turn
this off, because the flag would eventually get used.

**Never mount the Docker socket.** A container with the socket is not sandboxed; it is
root on the host with extra steps. ``tests/test_sandbox.py`` scans every constructed
command line for it, so the guarantee does not rest on nobody adding it later.

Resource limits are simultaneously a security control and a stability control. This runs
on a workstation where an unbounded Semgrep will happily take all 32 logical cores.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import pathlib
import re
import shutil
import subprocess
import tarfile
import time
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from agentsec.images import BUSYBOX, Image
from agentsec.log import get_logger

log = get_logger("agentsec.sandbox")


class SandboxError(Exception):
    """Something went wrong operating the sandbox, not inside it."""


class DockerUnavailableError(SandboxError):
    """Docker is not installed or the daemon is not running."""


WORKSPACE: Final = "/workspace"
SCRATCH: Final = "/scratch"

#: Every sandbox artifact carries this so the reaper can find leftovers from a crashed
#: run without guessing from names.
LABEL: Final = "agentsec.sandbox"
RUN_LABEL: Final = "agentsec.run"

#: nobody:nogroup. A scanner has no reason to be root, and a container escape that starts
#: as uid 0 is a materially different problem from one that starts as 65534.
NOBODY: Final = "65534:65534"

#: Docker's own volume-name grammar. Enforced rather than assumed, because it is what
#: makes a bind mount *unexpressible*: every way of writing a host path - an absolute
#: path, a relative one, a Windows drive letter, a UNC share - contains a character this
#: pattern rejects. A caller cannot smuggle one through the auxiliary-volume parameter.
_VOLUME_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")


def require_volume_name(name: str) -> str:
    """Reject anything that is not a plain Docker volume name."""
    if not _VOLUME_NAME.match(name):
        raise SandboxError(
            f"{name!r} is not a Docker volume name. Host paths are never mounted into a "
            "sandbox; stage files into a volume instead."
        )
    return name


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    """Caps applied to every sandboxed container.

    The defaults are sized for this project's workstation: two cores and 2 GB leave the
    host responsive while a scanner runs, and they are also what AS-004 caps the compose
    services at, so a full stack plus a scan stays well inside the WSL2 budget.
    """

    cpus: str = "2"
    memory: str = "2g"
    pids: int = 256
    timeout_seconds: float = 300.0
    scratch_size: str = "256m"

    def as_flags(self) -> list[str]:
        return [
            "--cpus",
            self.cpus,
            "--memory",
            self.memory,
            # Equal to --memory, which disables swap. Without it a container over its
            # memory cap swaps instead of failing, and the "limit" becomes a slow leak
            # into host swap - the exact way a workstation dies.
            "--memory-swap",
            self.memory,
            "--pids-limit",
            str(self.pids),
        ]


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """What a sandboxed command produced."""

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    image: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass
class Workspace:
    """A Docker volume holding one run's files.

    One volume per run, not one shared volume. Named volumes are persistent, so a shared
    one would carry a compromised run's leftovers into the next run's scan - and the
    evaluation would be measuring contamination.
    """

    run_id: str
    name: str
    staged: list[str] = field(default_factory=list)


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0  # noqa: S607
    )


class DockerSandbox:
    """Runs one-shot commands in an isolated container."""

    def __init__(
        self,
        *,
        limits: SandboxLimits | None = None,
        docker: str = "docker",
        utility_image: Image = BUSYBOX,
    ) -> None:
        self._limits = limits or SandboxLimits()
        self._docker = docker
        self._utility = utility_image

    @property
    def limits(self) -> SandboxLimits:
        return self._limits

    # ------------------------------------------------------------------ command shape

    def build_command(
        self,
        image: str,
        argv: Sequence[str],
        *,
        container_name: str,
        workspace: Workspace | None = None,
        writable_workspace: bool = False,
        network: bool = False,
        env: Mapping[str, str] | None = None,
        run_id: str = "adhoc",
        extra_volumes: Mapping[str, str] | None = None,
    ) -> list[str]:
        """Assemble the full ``docker run`` command line.

        Separated from execution so the security flags can be asserted without a daemon.
        Every hardening flag below is unconditional; the only knobs are the workspace, the
        network and the environment, and each defaults to the restrictive setting.
        """
        command = [
            self._docker,
            "run",
            "--rm",
            "--name",
            container_name,
            "--label",
            f"{LABEL}=true",
            "--label",
            f"{RUN_LABEL}={run_id}",
            # No capabilities at all, then no way to regain any. A scanner needs neither.
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            NOBODY,
            # Read-only root with an explicit noexec scratch: a payload that writes an
            # executable has nowhere to write it, and nowhere writable it can execute.
            "--read-only",
            "--tmpfs",
            f"{SCRATCH}:rw,noexec,nosuid,nodev,size={self._limits.scratch_size}",
            "--tmpfs",
            # S108 flags /tmp as an insecure temp path. It is not a host path: this is the
            # container's own tmpfs, mounted noexec precisely so a scanner that insists on
            # writing to /tmp has somewhere harmless to do it.
            f"/tmp:rw,noexec,nosuid,nodev,size={self._limits.scratch_size}",  # noqa: S108
            *self._limits.as_flags(),
        ]

        command += ["--network", "bridge"] if network else ["--network", "none"]

        if workspace is not None:
            mount = "rw" if writable_workspace else "ro"
            command += [
                "--volume",
                f"{require_volume_name(workspace.name)}:{WORKSPACE}:{mount}",
                "--workdir",
                WORKSPACE,
            ]

        # Auxiliary volumes are always read-only and always validated. They exist so a
        # scanner can be handed its ruleset or its vulnerability database without either
        # being mixed into the code under scan - and without the temptation to reach for a
        # bind mount to do it.
        for name, target in sorted((extra_volumes or {}).items()):
            command += ["--volume", f"{require_volume_name(name)}:{target}:ro"]

        for key, value in (env or {}).items():
            command += ["--env", f"{key}={value}"]

        command.append(image)
        command += list(argv)
        return command

    # ------------------------------------------------------------------ workspaces

    async def ensure_volume(self, name: str, *, run_id: str = "cache") -> str:
        """Create a named volume if it does not exist, and return its name.

        Used for caches that outlive a run - the Trivy database, most obviously. Kept
        separate from :meth:`workspace` because these are deliberately *not* reaped: the
        point of a cache volume is that the next run finds it already there.
        """
        require_volume_name(name)
        existing = await self._run_docker(["volume", "ls", "--quiet", "--filter", f"name=^{name}$"])
        if existing.strip() != name:
            await self._run_docker(["volume", "create", "--label", f"{RUN_LABEL}={run_id}", name])

        return name

    async def seed_volume(
        self,
        volume: str,
        image: str,
        argv: Sequence[str],
        *,
        mount: str = WORKSPACE,
        network: bool = False,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float = 600.0,
    ) -> SandboxResult:
        """Populate a cache volume, running as root.

        Provisioning, not analysis, and the distinction is the whole justification. This
        runs a *pinned* image with a *fixed* argv over *no untrusted input* - fetching
        Trivy's vulnerability database is the only current use. Nothing a planner or a
        scanned repository can influence reaches it.

        Root is needed because a fresh Docker volume is owned by ``root:root`` and the
        tool has to create directories inside it. An earlier version tried to chown the
        volume to uid 65534 and keep seeding unprivileged; the chown did not reliably
        persist through Docker Desktop's volume driver, and a control that works sometimes
        is worse than one that is absent, because it leaves a belief nobody re-checks.

        Everything untrusted still goes through :meth:`run`, as uid 65534, with the cache
        mounted read-only. Root writes the database; nobody reads it.

        The rules that are absolute stay absolute here: no host path, no Docker socket, no
        capabilities, no privilege escalation.
        """
        command = [
            self._docker,
            "run",
            "--rm",
            "--label",
            f"{LABEL}=true",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,size=2g",  # noqa: S108, F541 - container tmpfs, not a host path
            "--volume",
            f"{require_volume_name(volume)}:{mount}",
            *self._limits.as_flags(),
            "--network",
            "bridge" if network else "none",
        ]
        for key, value in (env or {}).items():
            command += ["--env", f"{key}={value}"]
        command += [image, *argv]

        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()
            return SandboxResult(
                exit_code=124,
                stdout="",
                stderr=f"seeding {volume} exceeded {timeout_seconds}s",
                duration_seconds=timeout_seconds,
                timed_out=True,
                image=image,
            )

        return SandboxResult(
            exit_code=process.returncode or 0,
            stdout=stdout.decode("utf-8", "replace"),
            stderr=stderr.decode("utf-8", "replace"),
            duration_seconds=0.0,
            image=image,
        )

    @contextlib.asynccontextmanager
    async def workspace(self, run_id: str) -> AsyncIterator[Workspace]:
        """Create a per-run volume and remove it however the block exits.

        Cleanup is in ``finally`` because the interesting exit is the one nobody plans
        for. A volume leaked on the crash path is exactly the volume holding whatever the
        run was doing when it crashed.
        """
        name = f"agentsec-ws-{run_id}-{uuid.uuid4().hex[:8]}"
        await self._run_docker(
            [
                "volume",
                "create",
                "--label",
                f"{LABEL}=true",
                "--label",
                f"{RUN_LABEL}={run_id}",
                name,
            ]
        )
        space = Workspace(run_id=run_id, name=name)
        log.info("sandbox workspace created", volume=name, run_id=run_id)
        try:
            yield space
        finally:
            await self._remove_volume(name)

    async def stage_into(self, volume: str, files: Mapping[str, str | bytes]) -> None:
        """Stage files into any named volume, by name rather than by workspace."""
        await self.stage(Workspace(run_id="stage", name=require_volume_name(volume)), files)

    async def stage(self, workspace: Workspace, files: Mapping[str, str | bytes]) -> None:
        """Copy files into the workspace volume over a tar stream.

        No bind mount is involved at any point. The alternative - mounting a host
        directory - is how a compromised scanner reaches the working tree, and there is no
        version of this project where that is an acceptable trade.
        """
        archive = _tar_bytes(files)
        command = [
            self._docker,
            "run",
            "--rm",
            "--interactive",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--volume",
            f"{require_volume_name(workspace.name)}:{WORKSPACE}",
            str(self._utility),
            "tar",
            "-xf",
            "-",
            "-C",
            WORKSPACE,
        ]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate(archive)
        if process.returncode != 0:
            raise SandboxError(f"staging failed: {stderr.decode('utf-8', 'replace')}")
        workspace.staged.extend(sorted(files))

    async def stage_directory(
        self, workspace: Workspace, source: pathlib.Path, *, prefix: str = ""
    ) -> None:
        """Stage a host directory's contents. Read on the host, written into the volume.

        The read is synchronous and deliberately so. Staging a fixture repository is a few
        hundred small files off a local disk; an async filesystem layer would add a
        dependency and a thread pool to save nothing measurable, and this runs once per
        sandbox rather than in a loop.
        """
        files: dict[str, str | bytes] = {}
        for path in sorted(source.rglob("*")):  # noqa: ASYNC240
            if path.is_file():
                relative = path.relative_to(source).as_posix()
                files[f"{prefix}{relative}" if prefix else relative] = path.read_bytes()
        await self.stage(workspace, files)

    async def read_file(self, workspace: Workspace, path: str) -> bytes:
        """Read one file back out of the workspace, again without a bind mount."""
        result = await self.run(
            str(self._utility),
            ["cat", f"{WORKSPACE}/{path}"],
            workspace=workspace,
            run_id=workspace.run_id,
            binary_stdout=True,
        )
        if not result.ok:
            raise SandboxError(f"could not read {path}: {result.stderr}")
        return result.stdout.encode("utf-8", "surrogateescape")

    # ------------------------------------------------------------------ execution

    async def run(
        self,
        image: str,
        argv: Sequence[str],
        *,
        workspace: Workspace | None = None,
        writable_workspace: bool = False,
        network: bool = False,
        env: Mapping[str, str] | None = None,
        run_id: str = "adhoc",
        timeout_seconds: float | None = None,
        binary_stdout: bool = False,
        extra_volumes: Mapping[str, str] | None = None,
    ) -> SandboxResult:
        """Run a command in the sandbox and return what it produced."""
        if shutil.which(self._docker) is None:
            raise DockerUnavailableError("docker is not on PATH")

        name = f"agentsec-sbx-{uuid.uuid4().hex[:12]}"
        command = self.build_command(
            image,
            argv,
            container_name=name,
            workspace=workspace,
            writable_workspace=writable_workspace,
            network=network,
            env=env,
            run_id=run_id,
            extra_volumes=extra_volumes,
        )
        limit = timeout_seconds if timeout_seconds is not None else self._limits.timeout_seconds
        started = time.monotonic()

        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=limit)
        except TimeoutError:
            # Killing the client process is not enough: `docker run` is a client, and the
            # container keeps running with nobody watching it. The container has to be
            # killed by name, which is why every run gets one.
            await self._kill_container(name)
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()
            duration = time.monotonic() - started
            log.warning("sandbox timed out", container=name, seconds=round(duration, 2))
            return SandboxResult(
                exit_code=124,
                stdout="",
                stderr=f"sandbox exceeded {limit}s and was terminated",
                duration_seconds=duration,
                timed_out=True,
                image=image,
            )

        duration = time.monotonic() - started
        decode = "surrogateescape" if binary_stdout else "replace"
        return SandboxResult(
            exit_code=process.returncode or 0,
            stdout=stdout.decode("utf-8", decode),
            stderr=stderr.decode("utf-8", "replace"),
            duration_seconds=duration,
            image=image,
        )

    # ------------------------------------------------------------------ internals

    async def _run_docker(self, args: Sequence[str]) -> str:
        process = await asyncio.create_subprocess_exec(
            self._docker,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise SandboxError(
                f"docker {' '.join(args)} failed: {stderr.decode('utf-8', 'replace')}"
            )
        return stdout.decode("utf-8", "replace").strip()

    async def _kill_container(self, name: str) -> None:
        with contextlib.suppress(SandboxError):
            await self._run_docker(["kill", name])

    async def _remove_volume(self, name: str) -> None:
        try:
            await self._run_docker(["volume", "rm", "--force", name])
            log.info("sandbox workspace removed", volume=name)
        except SandboxError as error:
            # Reported, never raised: a cleanup failure must not mask whatever the caller
            # was actually doing. The reaper collects anything left behind.
            log.warning("sandbox workspace not removed", volume=name, error=str(error))


def _tar_bytes(files: Mapping[str, str | bytes]) -> bytes:
    """Build an in-memory tar of the staged files.

    Modes are set explicitly rather than inherited: files staged from a Windows host carry
    permissions that mean nothing on Linux, and a workspace the sandbox user cannot read
    fails in a way that looks like a scanner bug.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in sorted(files):
            payload = files[name]
            data = payload.encode("utf-8") if isinstance(payload, str) else payload
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o644
            info.uid = 65534
            info.gid = 65534
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


__all__ = [
    "LABEL",
    "NOBODY",
    "RUN_LABEL",
    "SCRATCH",
    "WORKSPACE",
    "DockerSandbox",
    "DockerUnavailableError",
    "SandboxError",
    "SandboxLimits",
    "SandboxResult",
    "Workspace",
    "docker_available",
    "require_volume_name",
]
