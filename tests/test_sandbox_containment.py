"""Containment under real scanner load (AS-031B, AS-032).

``tests/test_sandbox.py`` proves the boundary holds for a busybox container. That is the
right place to start and the wrong place to stop: the containers that actually matter run
Semgrep and Trivy over attacker-authored source, and those images are larger, run more
code, and want more of the host than busybox ever asks for. A boundary demonstrated only
against `echo` is a boundary nobody has tested.

So everything here runs against the images the project actually uses, and the abuse probes
are the ones AS-032 names: traversal, network, timeout, oversized output, and process
pressure. All are harmless by construction — the point is to show the controls engage, not
to develop an exploit.

    uv run pytest -m sandbox
"""

from __future__ import annotations

import asyncio
import pathlib
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from agentsec.images import SEMGREP, TRIVY
from agentsec.sandbox import (
    DockerSandbox,
    SandboxError,
    SandboxLimits,
    Workspace,
    docker_available,
    find_leftovers,
    require_volume_name,
)
from agentsec.scanners.base import ScannerError, clamp
from agentsec.scanners.semgrep import SemgrepScanner

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "repos"

requires_docker = pytest.mark.skipif(not docker_available(), reason="Docker daemon not available")

#: The images that actually process untrusted input. Both are checked, because they carry
#: different entrypoints, users and default environments.
SCANNER_IMAGES = [str(SEMGREP), str(TRIVY)]


# =========================================================== structural, no daemon needed


def test_a_host_path_cannot_be_passed_as_an_auxiliary_volume() -> None:
    """The auxiliary-volume parameter is the one place a bind mount could be smuggled in.

    Docker's volume-name grammar is what makes that unexpressible: every way of writing a
    host path - absolute, relative, a Windows drive letter, a UNC share - contains a
    character the pattern rejects.
    """
    for candidate in (
        "/var/run",
        "./cache",
        "../cache",
        "C:\\Users\\darth",
        "//host/share",
        "vol:/workspace",
        "vol:/workspace:rw",
        "/var/run/docker.sock",
        "",
        "-not-a-name",
    ):
        with pytest.raises(SandboxError, match="not a Docker volume name"):
            require_volume_name(candidate)


def test_a_real_volume_name_is_accepted() -> None:
    for candidate in ("agentsec-trivy-cache", "agentsec_ws_1", "vol.2", "a"):
        assert require_volume_name(candidate) == candidate


# =========================================================== the scanner images


@pytest.mark.sandbox
@requires_docker
class TestScannerImagesAreContained:
    """AS-031B's acceptance criterion: the scanner runs *inside* the sandbox."""

    @pytest_asyncio.fixture
    async def sandbox(self) -> AsyncIterator[DockerSandbox]:
        yield DockerSandbox(limits=SandboxLimits(timeout_seconds=120))

    @pytest.mark.parametrize("image", SCANNER_IMAGES, ids=["semgrep", "trivy"])
    async def test_the_scanner_image_does_not_run_as_root(
        self, sandbox: DockerSandbox, image: str
    ) -> None:
        """Probes run through ``sh`` throughout this class: Trivy's image carries its own
        entrypoint, so a bare ``id -u`` would become ``trivy id -u`` and quietly answer a
        different question than the one being asked."""
        result = await sandbox.run(image, ["-c", "id -u"], entrypoint="sh")
        assert result.ok, result.stderr
        assert result.stdout.strip() == "65534"

    @pytest.mark.parametrize("image", SCANNER_IMAGES, ids=["semgrep", "trivy"])
    async def test_the_scanner_image_has_no_network(
        self, sandbox: DockerSandbox, image: str
    ) -> None:
        """Trivy in particular will reach for its database registry given the chance, and
        a scan that silently downloads is a scan whose result depends on the day it ran."""
        result = await sandbox.run(
            image, ["-c", "getent hosts registry-1.docker.io || exit 7"], entrypoint="sh"
        )
        assert not result.ok

    @pytest.mark.parametrize("image", SCANNER_IMAGES, ids=["semgrep", "trivy"])
    async def test_the_scanner_image_cannot_reach_the_docker_socket(
        self, sandbox: DockerSandbox, image: str
    ) -> None:
        result = await sandbox.run(image, ["-c", "test -S /var/run/docker.sock"], entrypoint="sh")
        assert not result.ok

    @pytest.mark.parametrize("image", SCANNER_IMAGES, ids=["semgrep", "trivy"])
    async def test_the_scanner_image_has_a_read_only_root(
        self, sandbox: DockerSandbox, image: str
    ) -> None:
        result = await sandbox.run(image, ["-c", "touch /evidence"], entrypoint="sh")
        assert not result.ok

    async def test_a_real_scan_runs_under_the_full_control_set(
        self, sandbox: DockerSandbox
    ) -> None:
        """The integration proof: a scan that finds the fixture's SQL injection, executed
        by a container with no network, no capabilities, a read-only root and a per-run
        volume that is not a bind mount."""
        scanner = SemgrepScanner(sandbox, timeout_seconds=120)
        async with sandbox.workspace("contained-scan") as space:
            await sandbox.stage_directory(space, FIXTURES / "repo-a")

            command = sandbox.build_command(
                str(SEMGREP), ["scan"], container_name="probe", workspace=space
            )
            assert command[command.index("--network") + 1] == "none"
            assert command[command.index("--cap-drop") + 1] == "ALL"
            assert "--read-only" in command
            assert f"{space.name}:/workspace:ro" in command

            result = await scanner.scan_repository(space)

        assert "agentsec.python.sql-injection-concat" in result.rule_ids()


# =========================================================== abuse probes


@pytest.mark.sandbox
@requires_docker
class TestAbuseProbes:
    """AS-032. Harmless by construction: each probe shows a control engaging."""

    @pytest_asyncio.fixture
    async def sandbox(self) -> AsyncIterator[DockerSandbox]:
        yield DockerSandbox(limits=SandboxLimits(timeout_seconds=120))

    async def test_a_traversal_out_of_the_workspace_finds_nothing_useful(
        self, sandbox: DockerSandbox
    ) -> None:
        """Escaping /workspace lands in the container's own root, not the host's.

        The check is deliberately positive as well as negative: it confirms the traversal
        *worked* and still reached nothing, rather than passing because the command failed
        for an unrelated reason.
        """
        async with sandbox.workspace("escape") as space:
            await sandbox.stage(space, {"marker.txt": "inside"})

            escaped = await sandbox.run(
                str(SEMGREP), ["-c", "ls /workspace/../.. 2>&1"], entrypoint="sh", workspace=space
            )
            assert escaped.ok, "the traversal itself should succeed; it just finds nothing"
            for entry in ("Users", "host_mnt", "OneDrive", "PErsonal_Github"):
                assert entry not in escaped.stdout

    async def test_the_workspace_cannot_be_written_through(self, sandbox: DockerSandbox) -> None:
        """A scanner that could edit the code under scan could edit away its own findings."""
        async with sandbox.workspace("write-through") as space:
            await sandbox.stage(space, {"a.py": "x = 1\n"})
            result = await sandbox.run(
                str(SEMGREP),
                ["-c", "echo tampered > /workspace/a.py"],
                entrypoint="sh",
                workspace=space,
            )
            assert not result.ok

            unchanged = await sandbox.run(
                str(SEMGREP), ["-c", "cat /workspace/a.py"], workspace=space, entrypoint="sh"
            )
            assert unchanged.stdout.strip() == "x = 1"

    async def test_process_pressure_hits_the_pid_limit_rather_than_the_host(
        self, sandbox: DockerSandbox
    ) -> None:
        """A bounded fork probe. Not a fork bomb: the loop counts, and the cgroup stops it
        well before the count does. What is being shown is that the *host* never sees the
        pressure, which on a shared workstation is the difference between a failed test and
        a reboot."""
        limited = DockerSandbox(limits=SandboxLimits(pids=32, timeout_seconds=60))
        result = await limited.run(
            str(SEMGREP),
            ["-c", "i=0; while [ $i -lt 200 ]; do sleep 10 & i=$((i+1)); done; echo SPAWNED_ALL"],
            entrypoint="sh",
            timeout_seconds=45,
        )
        assert "SPAWNED_ALL" not in result.stdout, "the PID limit did not engage"

    async def test_a_hang_during_a_scan_is_terminated(self, sandbox: DockerSandbox) -> None:
        async with sandbox.workspace("hang") as space:
            await sandbox.stage(space, {"a.py": "x = 1\n"})
            result = await sandbox.run(
                str(SEMGREP),
                ["-c", "sleep 120"],
                workspace=space,
                entrypoint="sh",
                timeout_seconds=4,
            )

        assert result.timed_out
        assert result.duration_seconds < 30
        async with asyncio.timeout(30):
            # Polling a Docker listing: the state lives in the daemon, not this process.
            while find_leftovers().containers:  # noqa: ASYNC110
                await asyncio.sleep(0.5)

    async def test_large_output_is_captured_without_deadlocking(
        self, sandbox: DockerSandbox
    ) -> None:
        """A container writing megabytes to a pipe nobody drains blocks forever.

        This is a real failure mode rather than a hypothetical: a repository crafted to
        produce enormous scanner output would hang the run rather than fail it, and a hung
        run is the hardest kind to diagnose.
        """
        async with asyncio.timeout(120):
            result = await sandbox.run(
                str(SEMGREP),
                ["-c", "head -c 4000000 /dev/zero | tr '\\0' 'x'"],
                entrypoint="sh",
                timeout_seconds=90,
            )

        assert result.ok, result.stderr[:300]
        assert len(result.stdout) >= 4_000_000

    async def test_oversized_output_is_truncated_rather_than_trusted(self) -> None:
        """And the caller is told. A result built from partial output must never be
        mistaken for a complete one."""
        payload = "x" * 5_000_000
        text, truncated = clamp(payload, 4 * 1024 * 1024)
        assert truncated is True
        assert len(text) == 4 * 1024 * 1024

        from agentsec.scanners.semgrep import _parse

        with pytest.raises(ScannerError, match="size cap"):
            _parse('{"results": [{"check_id": "trunc', truncated=True)

    async def test_a_second_run_cannot_read_the_first_run_workspace(
        self, sandbox: DockerSandbox
    ) -> None:
        """Per-run volumes, checked from inside rather than by comparing names.

        A shared workspace would carry one run's attacker-authored source into the next
        run's scan, and the evaluation would be measuring contamination.
        """
        async with sandbox.workspace("run-first") as first:
            await sandbox.stage(first, {"payload.py": "# from the first run\n"})
            leaked_name = first.name

            async with sandbox.workspace("run-second") as second:
                listing = await sandbox.run(
                    str(SEMGREP), ["-c", "ls -a"], workspace=second, entrypoint="sh"
                )
                assert "payload.py" not in listing.stdout

                mounted = sandbox.build_command(
                    str(SEMGREP), ["ls"], container_name="p", workspace=second
                )
                assert leaked_name not in " ".join(mounted)

    async def test_an_unknown_auxiliary_volume_never_becomes_a_bind_mount(
        self, sandbox: DockerSandbox
    ) -> None:
        with pytest.raises(SandboxError):
            await sandbox.run(
                str(SEMGREP),
                ["ls"],
                extra_volumes={"/var/run": "/host"},
            )

    async def test_the_workspace_of_a_crashed_scan_is_reclaimed(
        self, sandbox: DockerSandbox
    ) -> None:
        name = ""
        scanner = SemgrepScanner(sandbox, timeout_seconds=60)
        with pytest.raises(ScannerError):
            async with sandbox.workspace("crash-scan") as space:
                name = space.name
                await sandbox.stage(space, {"a.py": "x = 1\n"})
                await scanner.scan_path(space, "does-not-exist.py")

        assert name
        assert name not in find_leftovers().volumes


def test_the_probe_images_are_the_ones_actually_used() -> None:
    """Guards against these probes drifting onto some other image and proving nothing
    about the containers that process untrusted input."""
    assert [str(SEMGREP), str(TRIVY)] == SCANNER_IMAGES
    assert all("@sha256:" in image for image in SCANNER_IMAGES)


def test_workspace_is_a_plain_data_object() -> None:
    """It crosses no trust boundary and holds no handle: a Workspace is a volume name and
    a run id, so passing one around cannot smuggle authority."""
    space = Workspace(run_id="r", name="agentsec-ws-r-1")
    assert set(vars(space)) == {"run_id", "name", "staged"}
