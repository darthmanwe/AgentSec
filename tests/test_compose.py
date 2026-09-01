"""Compose stack tests (AS-004).

The important one is `test_compose_images_match_the_pin_source`. docker-compose.yml
repeats the digests from scripts/images.py inline so that `docker compose config` shows
what actually runs rather than a wall of variable substitutions. That duplication is only
safe because this test fails when the two disagree.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from images import COMPOSE_IMAGES, TOOL_IMAGES  # noqa: E402

CORE_SERVICES = {"postgres", "opa", "temporal"}
PROFILED_SERVICES = {"temporal-ui": "ui", "prometheus": "observability", "grafana": "observability"}


@pytest.fixture(scope="module")
def compose_text() -> str:
    return COMPOSE_FILE.read_text(encoding="utf-8")


def test_compose_file_exists() -> None:
    assert COMPOSE_FILE.exists()


def test_every_image_is_digest_pinned(compose_text: str) -> None:
    """A tag is a mutable pointer. Pinning by tag means a rebuilt image silently changes
    what a published benchmark ran against."""
    images = re.findall(r"^\s+image:\s*(\S+)\s*$", compose_text, re.M)
    assert images, "no images found in docker-compose.yml"
    for image in images:
        assert "@sha256:" in image, f"image is not digest-pinned: {image}"


def test_compose_images_match_the_pin_source(compose_text: str) -> None:
    """scripts/images.py is the single source of truth; this is the anti-drift check."""
    for service, image in COMPOSE_IMAGES.items():
        block = re.search(
            rf"^  {re.escape(service)}:\n(.*?)(?=^  \S|\Z)", compose_text, re.M | re.S
        )
        assert block, f"service {service} not found in docker-compose.yml"
        found = re.search(r"^\s+image:\s*(\S+)\s*$", block.group(1), re.M)
        assert found, f"service {service} has no image line"
        assert found.group(1) == image.reference, (
            f"{service}: compose has {found.group(1)}, scripts/images.py has {image.reference}"
        )


def test_digests_are_well_formed() -> None:
    for image in {**COMPOSE_IMAGES, **TOOL_IMAGES}.values():
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", image.digest), image.digest


def test_observability_is_behind_a_profile(compose_text: str) -> None:
    """S0-S2 must run three services, not five. Prometheus and Grafana are not needed
    until AS-041."""
    for service, profile in PROFILED_SERVICES.items():
        block = re.search(
            rf"^  {re.escape(service)}:\n(.*?)(?=^  \S|\Z)", compose_text, re.M | re.S
        )
        assert block, f"service {service} missing"
        assert f'profiles: ["{profile}"]' in block.group(1), (
            f"{service} must be behind the {profile!r} profile"
        )


def test_core_services_have_no_profile(compose_text: str) -> None:
    for service in CORE_SERVICES:
        block = re.search(
            rf"^  {re.escape(service)}:\n(.*?)(?=^  \S|\Z)", compose_text, re.M | re.S
        )
        assert block, f"service {service} missing"
        assert "profiles:" not in block.group(1), f"{service} must start by default"


def test_every_service_has_resource_limits(compose_text: str) -> None:
    """WSL2 defaults to half the host RAM and every logical processor; unbounded services
    on a shared workstation is how a machine ends up in swap."""
    for service in {*CORE_SERVICES, *PROFILED_SERVICES}:
        block = re.search(
            rf"^  {re.escape(service)}:\n(.*?)(?=^  \S|\Z)", compose_text, re.M | re.S
        )
        assert block, f"service {service} missing"
        body = block.group(1)
        assert "cpus:" in body, f"{service} has no CPU limit"
        assert "memory:" in body, f"{service} has no memory limit"


def test_core_services_have_healthchecks(compose_text: str) -> None:
    for service in CORE_SERVICES:
        block = re.search(
            rf"^  {re.escape(service)}:\n(.*?)(?=^  \S|\Z)", compose_text, re.M | re.S
        )
        assert block and "healthcheck:" in block.group(1), f"{service} has no healthcheck"


def test_policy_is_mounted_read_only(compose_text: str) -> None:
    """The policy bundle is trusted input. OPA must not be able to rewrite the rules it
    is enforcing."""
    assert "./policy:/policy:ro" in compose_text


def test_no_docker_socket_is_mounted(compose_text: str) -> None:
    """Mounting the Docker socket into any service would hand it host-root equivalence
    and void the sandbox story before it is written."""
    assert "docker.sock" not in compose_text


def test_development_credentials_are_marked(compose_text: str) -> None:
    """Weak credentials are committed deliberately so the stack starts with no setup.
    They must be unmistakably labelled so nobody promotes them."""
    for line in compose_text.splitlines():
        if "PASSWORD:" in line or "PWD:" in line:
            assert "DEVELOPMENT ONLY" in line, f"unmarked credential: {line.strip()}"


# --------------------------------------------------------------------------- toolbox


def test_toolbox_builds_a_hardened_command() -> None:
    from toolbox import build_command

    cmd = build_command("opa", ["test", "policy"])
    joined = " ".join(cmd)
    assert "--network none" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--cpus" in joined and "--memory" in joined
    assert ":ro" in joined, "workspace must be mounted read-only"
    assert TOOL_IMAGES["opa"].reference in cmd


def test_toolbox_rewrites_host_paths_to_container_paths() -> None:
    from toolbox import to_container_path

    assert to_container_path("policy") == "/workspace/policy"
    assert to_container_path("--strict") == "--strict"
    assert to_container_path("does-not-exist") == "does-not-exist"


# --------------------------------------------------------------------------- live docker


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_docker_compose_config_validates() -> None:
    """The AS-004 acceptance criterion, run against the real compose implementation."""
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
