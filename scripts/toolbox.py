"""Run pinned tool containers (AS-004).

`opa`, `trivy` and `semgrep` are not installed on the development host, and requiring
them would break the "clean setup reproducible from the README" gate. Semgrep in
particular has no supported native Windows install, so a host-installed path was never
available here.

Everything runs as a one-shot container at a pinned digest, with resource caps, no
network unless explicitly needed, and a read-only workspace mount.

    python scripts/toolbox.py opa test policy
    python scripts/toolbox.py opa check --strict policy
    python scripts/toolbox.py opa fmt --list policy

Paths are resolved against the repository root and converted to container paths, so the
same command works from Git Bash, PowerShell and CI without the caller thinking about it.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from images import TOOL_IMAGES

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKSPACE = "/workspace"

#: Caps for one-shot tool containers. Scanners are happy to use every core they can see,
#: which on this host is 32 of them.
CPU_LIMIT = "2"
MEMORY_LIMIT = "2g"


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "info"],  # noqa: S607
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def to_container_path(value: str) -> str:
    """Rewrite a host path argument into its location under the workspace mount.

    Anything that is not an existing path is passed through untouched, so flags and
    non-path arguments survive.
    """
    candidate = pathlib.Path(value)
    resolved = candidate if candidate.is_absolute() else (REPO_ROOT / candidate)
    try:
        if not resolved.exists():
            return value
        relative = resolved.resolve().relative_to(REPO_ROOT)
    except ValueError:
        # Outside the repository: cannot be mounted, so leave it and let the tool complain.
        return value
    return f"{WORKSPACE}/{relative.as_posix()}"


def build_command(tool: str, args: list[str], *, network: bool = False) -> list[str]:
    image = TOOL_IMAGES.get(tool)
    if image is None:
        raise SystemExit(f"unknown tool {tool!r}; known: {', '.join(sorted(TOOL_IMAGES))}")

    cmd = [
        "docker",
        "run",
        "--rm",
        "--cpus",
        CPU_LIMIT,
        "--memory",
        MEMORY_LIMIT,
        "--pids-limit",
        "512",
        "--security-opt",
        "no-new-privileges",
        # The workspace is read-only: a linter has no business writing to the tree it is
        # checking, and `opa fmt --write` should fail loudly rather than silently succeed.
        "--volume",
        f"{REPO_ROOT}:{WORKSPACE}:ro",
        "--workdir",
        WORKSPACE,
        "--entrypoint",
        "",
    ]
    if not network:
        cmd += ["--network", "none"]
    cmd += [image.reference, f"/{tool}", *[to_container_path(a) for a in args]]
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=sorted(TOOL_IMAGES), help="which pinned tool to run")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments passed to the tool")
    parser.add_argument(
        "--network",
        action="store_true",
        help="allow network access (off by default; nothing offline-reproducible needs it)",
    )
    parsed = parser.parse_args()

    if not docker_available():
        print(
            "Docker is not available. Start Docker Desktop, or run "
            "`pwsh -File scripts/preflight.ps1` to diagnose.",
            file=sys.stderr,
        )
        return 2

    cmd = build_command(parsed.tool, parsed.args, network=parsed.network)
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, check=False).returncode  # noqa: S603


if __name__ == "__main__":
    raise SystemExit(main())
