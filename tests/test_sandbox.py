"""Sandbox containment tests (AS-031A).

Two layers, deliberately.

The **structural** tests read the command line the runner builds and need no daemon. They
catch the class of mistake that matters most: a hardening flag quietly dropped, or a
Docker socket mount added by someone solving an unrelated problem. They run in CI on every
push, where the container tests cannot.

The **containment** tests actually start containers and check the boundary holds from the
inside. A flag being present in an argv is not evidence that the kernel honoured it.

    uv run pytest -m sandbox
"""

from __future__ import annotations

import asyncio
import pathlib
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from agentsec.images import BUSYBOX
from agentsec.sandbox import (
    LABEL,
    NOBODY,
    RUN_LABEL,
    DockerSandbox,
    SandboxLimits,
    Workspace,
    docker_available,
    find_leftovers,
    reap,
)

BUSY = str(BUSYBOX)

requires_docker = pytest.mark.skipif(not docker_available(), reason="Docker daemon not available")


# =========================================================== structural: no daemon needed


@pytest.fixture
def sandbox() -> DockerSandbox:
    return DockerSandbox()


def command_for(sandbox: DockerSandbox, **kwargs: object) -> list[str]:
    return sandbox.build_command(
        BUSY,
        ["true"],
        container_name="agentsec-sbx-test",
        **kwargs,  # type: ignore[arg-type]
    )


def test_the_docker_socket_is_never_mounted(sandbox: DockerSandbox) -> None:
    """The one that would make everything else meaningless.

    A container with the Docker socket is not sandboxed; it is root on the host with extra
    steps. This scans the whole command line rather than checking a flag, because the
    socket can arrive as a volume, a mount, or a bare path in an argument.
    """
    workspace = Workspace(run_id="r1", name="agentsec-ws-r1")
    for kwargs in ({}, {"workspace": workspace}, {"network": True}, {"writable_workspace": True}):
        rendered = " ".join(command_for(sandbox, **kwargs))
        assert "docker.sock" not in rendered
        assert "/var/run/docker" not in rendered
        assert r"\\.\pipe\docker" not in rendered


def test_no_host_path_is_ever_bind_mounted(sandbox: DockerSandbox) -> None:
    """Volumes are named volumes. A bind mount is spelled with a host path on the left of
    the colon, and there is no code path that produces one."""
    workspace = Workspace(run_id="r1", name="agentsec-ws-r1")
    command = command_for(sandbox, workspace=workspace)
    mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--volume"]

    assert mounts == ["agentsec-ws-r1:/workspace:ro"]
    for mount in mounts:
        source = mount.split(":")[0]
        assert not source.startswith(("/", ".", "~")), f"bind mount: {mount}"
        assert ":\\" not in source and ":/" not in source


def test_the_network_is_off_by_default(sandbox: DockerSandbox) -> None:
    command = command_for(sandbox)
    assert command[command.index("--network") + 1] == "none"


def test_the_network_must_be_asked_for_explicitly(sandbox: DockerSandbox) -> None:
    command = command_for(sandbox, network=True)
    assert command[command.index("--network") + 1] == "bridge"


def test_the_workspace_is_read_only_unless_asked_otherwise(sandbox: DockerSandbox) -> None:
    workspace = Workspace(run_id="r1", name="vol")
    assert "vol:/workspace:ro" in command_for(sandbox, workspace=workspace)
    assert "vol:/workspace:rw" in command_for(sandbox, workspace=workspace, writable_workspace=True)


@pytest.mark.parametrize(
    "flag",
    ["--rm", "--read-only", "--cap-drop", "--security-opt", "--user", "--tmpfs", "--name"],
)
def test_every_hardening_flag_is_unconditional(sandbox: DockerSandbox, flag: str) -> None:
    """Unconditional, not defaulted. A hardening flag with an off switch is a hardening
    flag that will eventually be switched off to make something work."""
    for kwargs in ({}, {"network": True}, {"writable_workspace": True}):
        assert flag in command_for(sandbox, **kwargs), f"{flag} missing with {kwargs}"


def test_the_container_does_not_run_as_root(sandbox: DockerSandbox) -> None:
    command = command_for(sandbox)
    assert command[command.index("--user") + 1] == NOBODY
    assert not NOBODY.startswith("0:")


def test_privilege_escalation_is_blocked(sandbox: DockerSandbox) -> None:
    command = command_for(sandbox)
    options = [command[i + 1] for i, arg in enumerate(command) if arg == "--security-opt"]
    assert "no-new-privileges" in options
    assert command[command.index("--cap-drop") + 1] == "ALL"


def test_scratch_space_is_not_executable(sandbox: DockerSandbox) -> None:
    """A payload that writes an executable must have nowhere to run it from."""
    command = command_for(sandbox)
    tmpfs = [command[i + 1] for i, arg in enumerate(command) if arg == "--tmpfs"]
    assert tmpfs, "no scratch space mounted"
    for mount in tmpfs:
        assert "noexec" in mount and "nosuid" in mount, mount


def test_every_limit_is_applied(sandbox: DockerSandbox) -> None:
    command = command_for(sandbox)
    for flag in ("--cpus", "--memory", "--memory-swap", "--pids-limit"):
        assert flag in command, f"{flag} missing"


def test_swap_is_disabled_by_matching_the_memory_cap() -> None:
    """Without this a container over its memory cap swaps rather than failing, and the
    "limit" becomes a slow leak into host swap - which is how a workstation dies."""
    flags = SandboxLimits(memory="1g").as_flags()
    assert flags[flags.index("--memory") + 1] == flags[flags.index("--memory-swap") + 1]


def test_containers_are_labelled_for_the_reaper(sandbox: DockerSandbox) -> None:
    command = command_for(sandbox, run_id="run-42")
    labels = [command[i + 1] for i, arg in enumerate(command) if arg == "--label"]
    assert f"{LABEL}=true" in labels
    assert f"{RUN_LABEL}=run-42" in labels


def test_the_image_reference_is_digest_pinned() -> None:
    """A moving tag silently changes what a published benchmark ran against."""
    assert "@sha256:" in BUSY


# =========================================================== containment: real containers


@pytest.mark.sandbox
@requires_docker
class TestContainment:
    """The boundary, checked from inside the container."""

    @pytest_asyncio.fixture
    async def sandbox(self) -> AsyncIterator[DockerSandbox]:
        yield DockerSandbox(limits=SandboxLimits(timeout_seconds=60))

    async def test_a_trivial_command_runs_under_every_limit(self, sandbox: DockerSandbox) -> None:
        """The AS-031A acceptance criterion, and it needs no scanner code to pass."""
        result = await sandbox.run(BUSY, ["echo", "hello from the sandbox"])
        assert result.ok, result.stderr
        assert result.stdout.strip() == "hello from the sandbox"

    async def test_the_network_is_unreachable(self, sandbox: DockerSandbox) -> None:
        result = await sandbox.run(BUSY, ["wget", "-T", "3", "-q", "-O", "-", "http://example.com"])
        assert not result.ok, "the sandbox reached the network"

    async def test_the_host_filesystem_is_not_visible(self, sandbox: DockerSandbox) -> None:
        """The repository lives on a OneDrive-synced path on this host. A sandbox that can
        read it can read everything the developer has."""
        result = await sandbox.run(BUSY, ["ls", "/host_mnt"])
        assert not result.ok

        listing = await sandbox.run(BUSY, ["ls", "/"])
        assert listing.ok
        for entry in ("Users", "host_mnt", "mnt", "workspace"):
            assert entry not in listing.stdout.split(), f"{entry} is visible in the sandbox"

    async def test_the_docker_socket_is_absent(self, sandbox: DockerSandbox) -> None:
        result = await sandbox.run(BUSY, ["ls", "-l", "/var/run/docker.sock"])
        assert not result.ok, "the Docker socket is reachable from inside the sandbox"

    async def test_the_root_filesystem_is_read_only(self, sandbox: DockerSandbox) -> None:
        result = await sandbox.run(BUSY, ["touch", "/evidence"])
        assert not result.ok

    async def test_scratch_is_writable_but_not_executable(self, sandbox: DockerSandbox) -> None:
        written = await sandbox.run(
            BUSY, ["sh", "-c", "echo ok > /scratch/probe && cat /scratch/probe"]
        )
        assert written.ok, written.stderr

        executed = await sandbox.run(
            BUSY,
            [
                "sh",
                "-c",
                "printf '#!/bin/sh\\necho ran\\n' > /scratch/p"
                " && chmod +x /scratch/p && /scratch/p",
            ],
        )
        assert not executed.ok, "an executable ran from noexec scratch"

    async def test_it_does_not_run_as_root(self, sandbox: DockerSandbox) -> None:
        result = await sandbox.run(BUSY, ["id", "-u"])
        assert result.ok
        assert result.stdout.strip() == "65534"

    async def test_the_limits_are_visible_to_the_kernel(self, sandbox: DockerSandbox) -> None:
        """A flag in an argv is not evidence the kernel honoured it.

        The cgroup filesystem reports what is actually in force. Both hierarchy versions
        are read because the answer differs by host, not by anything this project
        controls: Docker Desktop on WSL2 is v2, and a CI runner may be either.
        """
        limited = DockerSandbox(limits=SandboxLimits(memory="512m", pids=64, cpus="1"))

        async def read_first(*paths: str) -> str:
            for path in paths:
                result = await limited.run(BUSY, ["cat", path])
                if result.ok:
                    return result.stdout.strip()
            pytest.skip(f"no cgroup file among {paths}; cannot observe the limit here")

        memory = await read_first(
            "/sys/fs/cgroup/memory.max",  # v2
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",  # v1
        )
        assert int(memory) == 512 * 1024 * 1024

        pids = await read_first("/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max")
        assert pids == "64"

        cpu = await read_first("/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        parts = cpu.split()
        quota = int(parts[0])
        period = int(parts[1]) if len(parts) > 1 else 100_000  # v1 keeps period in its own file
        assert quota / period == pytest.approx(1.0)

    async def test_a_timeout_terminates_the_container(self, sandbox: DockerSandbox) -> None:
        """The container has to die, not merely the client watching it. `docker run` is a
        client; killing it leaves the container running with nobody watching."""
        result = await sandbox.run(BUSY, ["sleep", "60"], timeout_seconds=3)

        assert result.timed_out
        assert result.exit_code == 124
        assert result.duration_seconds < 30

        # Polling a Docker listing, so there is no Event to wait on: the state being
        # observed lives in the daemon, not in this process.
        async with asyncio.timeout(30):
            while find_leftovers().containers:  # noqa: ASYNC110
                await asyncio.sleep(0.5)


@pytest.mark.sandbox
@requires_docker
class TestWorkspaces:
    """Per-run volumes: staged without a bind mount, and always reclaimed."""

    @pytest_asyncio.fixture
    async def sandbox(self) -> AsyncIterator[DockerSandbox]:
        yield DockerSandbox(limits=SandboxLimits(timeout_seconds=60))

    async def test_files_are_staged_and_readable(self, sandbox: DockerSandbox) -> None:
        async with sandbox.workspace("run-stage") as space:
            await sandbox.stage(space, {"a.py": "print('hello')\n", "nested/b.txt": b"bytes"})

            listing = await sandbox.run(BUSY, ["find", ".", "-type", "f"], workspace=space)
            assert listing.ok, listing.stderr
            assert "./a.py" in listing.stdout
            assert "./nested/b.txt" in listing.stdout

            content = await sandbox.run(BUSY, ["cat", "a.py"], workspace=space)
            assert content.stdout.strip() == "print('hello')"

    async def test_a_staged_workspace_is_read_only_to_the_sandbox(
        self, sandbox: DockerSandbox
    ) -> None:
        async with sandbox.workspace("run-ro") as space:
            await sandbox.stage(space, {"a.py": "x = 1\n"})
            result = await sandbox.run(BUSY, ["touch", "/workspace/new"], workspace=space)
            assert not result.ok

    async def test_a_host_directory_stages_without_a_bind_mount(
        self, sandbox: DockerSandbox, tmp_path: pathlib.Path
    ) -> None:
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "mod.py").write_text("VALUE = 42\n", encoding="utf-8")

        async with sandbox.workspace("run-dir") as space:
            await sandbox.stage_directory(space, tmp_path)
            result = await sandbox.run(BUSY, ["cat", "pkg/mod.py"], workspace=space)
            assert result.stdout.strip() == "VALUE = 42"

    async def test_the_volume_is_removed_after_a_successful_run(
        self, sandbox: DockerSandbox
    ) -> None:
        async with sandbox.workspace("run-clean") as space:
            name = space.name
            assert name in find_leftovers(run_id="run-clean").volumes

        assert name not in find_leftovers().volumes

    async def test_the_volume_is_removed_after_a_crash(self, sandbox: DockerSandbox) -> None:
        """Cleanup is in ``finally`` because the interesting exit is the unplanned one -
        the volume leaked on the crash path holds whatever the run was doing when it died,
        which for this project means attacker-authored source."""
        name = ""
        with pytest.raises(RuntimeError, match="induced"):
            async with sandbox.workspace("run-crash") as space:
                name = space.name
                await sandbox.stage(space, {"payload.py": "# attacker authored\n"})
                raise RuntimeError("induced crash")

        assert name
        assert name not in find_leftovers().volumes

    async def test_two_runs_do_not_share_a_workspace(self, sandbox: DockerSandbox) -> None:
        """A shared volume would carry one run's leftovers into the next run's scan, and
        the evaluation would be measuring contamination."""
        async with sandbox.workspace("run-a") as first:
            await sandbox.stage(first, {"secret.txt": "from run a"})
            async with sandbox.workspace("run-b") as second:
                assert second.name != first.name
                result = await sandbox.run(BUSY, ["ls"], workspace=second)
                assert "secret.txt" not in result.stdout

    async def test_the_reaper_collects_a_leaked_volume(self, sandbox: DockerSandbox) -> None:
        """The runner's ``finally`` covers every exit it gets to observe. A killed process
        or a daemon restart is not one of those, so something has to collect the rest."""
        leaked = Workspace(run_id="run-leak", name="agentsec-ws-run-leak-deadbeef")
        # Reaching past the public API on purpose: simulating a leak means creating a
        # volume the runner will not clean up, which the runner has no method for.
        await sandbox._run_docker(
            [
                "volume",
                "create",
                "--label",
                f"{LABEL}=true",
                "--label",
                f"{RUN_LABEL}=run-leak",
                leaked.name,
            ]
        )
        assert leaked.name in find_leftovers(run_id="run-leak").volumes

        report = reap(run_id="run-leak")

        assert leaked.name in report.volumes
        assert leaked.name not in find_leftovers().volumes

    async def test_the_reaper_finds_nothing_when_nothing_leaked(self) -> None:
        assert reap(run_id="run-that-never-existed").total == 0
