"""Pinned container images — the single source of truth (AS-004).

Every image is pinned **by digest**, not by tag. A tag is a mutable pointer: pinning
`opa:1.20.1` means a rebuilt tag silently changes what a published benchmark ran against,
and reproducibility is the one property this project cannot trade away.

`docker-compose.yml` repeats these values inline, because a compose file full of variable
substitutions is unreadable and `docker compose config` should show what actually runs.
`tests/test_compose.py` asserts the two agree, so the duplication cannot drift — the same
generated-and-verified discipline the execution package uses.

To update a pin:

    docker buildx imagetools inspect <image>:<tag> --format "{{.Manifest.Digest}}"

then change it here *and* in docker-compose.yml, and run `uv run task test`.
"""

from __future__ import annotations

from typing import Final


class Image:
    """An image pinned to an immutable digest."""

    __slots__ = ("digest", "note", "repository", "tag")

    def __init__(self, repository: str, tag: str, digest: str, note: str = "") -> None:
        self.repository = repository
        self.tag = tag
        self.digest = digest
        self.note = note

    @property
    def reference(self) -> str:
        """The full pinned reference passed to Docker.

        The tag is retained alongside the digest purely for human readability; Docker
        resolves on the digest and ignores the tag when both are present.
        """
        return f"{self.repository}:{self.tag}@{self.digest}"

    def __str__(self) -> str:
        return self.reference


POSTGRES: Final = Image(
    "postgres",
    "17-alpine",
    "sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73",
)

OPA: Final = Image(
    "openpolicyagent/opa",
    "1.20.1",
    "sha256:39daf255ae7f25d81103f03a0c18308a50b7b5bb67907bed6166f70e24a970ff",
    note="1.x mandates Rego v1 syntax: `if` and `contains` are required on all rules.",
)

TEMPORAL: Final = Image(
    "temporalio/auto-setup",
    "1.29.7",
    "sha256:f14912b699cf73015ad5c4fc18d522d4b014db90e794039214dfb7c022c2644f",
    note=(
        "The published auto-setup image lags the Temporal source release: 1.31.2 exists "
        "on GitHub but the highest auto-setup tag on Docker Hub is 1.29.7 (verified "
        "2026-08-31; 1.30.0 and 1.31.x both return 404). Server 1.29.7 with Python SDK "
        "1.32.0 is a supported pairing."
    ),
)

TEMPORAL_UI: Final = Image(
    "temporalio/ui",
    "2.53.3",
    "sha256:eef301146e60fad34b47adaecfae4149016e34b2d44ba94fca5fd8e5441f182a",
)

PROMETHEUS: Final = Image(
    "prom/prometheus",
    "v3.7.3",
    "sha256:49214755b6153f90a597adcbff0252cc61069f8ab69ce8411285cd4a560e8038",
)

GRAFANA: Final = Image(
    "grafana/grafana",
    "12.3.1",
    "sha256:2175aaa91c96733d86d31cf270d5310b278654b03f5718c59de12a865380a31f",
)

#: Images referenced by docker-compose.yml, keyed by service name.
COMPOSE_IMAGES: Final[dict[str, Image]] = {
    "postgres": POSTGRES,
    "opa": OPA,
    "temporal": TEMPORAL,
    "temporal-ui": TEMPORAL_UI,
    "prometheus": PROMETHEUS,
    "grafana": GRAFANA,
}

#: One-shot tool containers, run by scripts/toolbox.py rather than compose. None of these
#: binaries are installed on the development host, and requiring them would break the
#: "clean setup reproducible from the README" gate.
TOOL_IMAGES: Final[dict[str, Image]] = {
    "opa": OPA,
}

__all__ = [
    "COMPOSE_IMAGES",
    "GRAFANA",
    "OPA",
    "POSTGRES",
    "PROMETHEUS",
    "TEMPORAL",
    "TEMPORAL_UI",
    "TOOL_IMAGES",
    "Image",
]
