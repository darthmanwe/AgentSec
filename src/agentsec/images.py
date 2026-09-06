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

BUSYBOX: Final = Image(
    "busybox",
    "1.37-musl",
    "sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23",
    note=(
        "The sandbox utility image (AS-031A). Used to stage a workspace into a Docker "
        "volume over a tar stream and to read results back out, so no host path is ever "
        "bind-mounted into a sandbox. Deliberately not the scanner image: staging must "
        "not depend on whatever tools a scanner image happens to ship."
    ),
)

SEMGREP: Final = Image(
    "semgrep/semgrep",
    "1.175.0",
    "sha256:b94b53d02fd4a022f9eac4e2af1380f5c3c4c21400e79d3336bdff1d1db5e796",
    note=(
        "Run against first-party rules only (AS-029). Semgrep's community registry rules "
        "are under the Semgrep Rules License v1.0 - internal, non-competing use - which "
        "is not defensible to vendor into a public portfolio repository. Opengrep is a "
        "drop-in for anyone wanting registry-equivalent coverage."
    ),
)

TRIVY: Final = Image(
    "aquasec/trivy",
    "0.74.0",
    "sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969",
    note=(
        "Ships WITHOUT its vulnerability database and fetches it on first run (AS-030). "
        "The database is staged into a cache volume ahead of time and every scan runs "
        "--skip-db-update --offline-scan, because a database that silently updates "
        "between runs makes published numbers irreproducible."
    ),
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
    "busybox": BUSYBOX,
    "semgrep": SEMGREP,
    "trivy": TRIVY,
}

__all__ = [
    "BUSYBOX",
    "COMPOSE_IMAGES",
    "GRAFANA",
    "OPA",
    "POSTGRES",
    "PROMETHEUS",
    "SEMGREP",
    "TEMPORAL",
    "TEMPORAL_UI",
    "TOOL_IMAGES",
    "TRIVY",
    "Image",
]
