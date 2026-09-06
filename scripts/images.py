"""Compatibility shim: the pins live in the package (AS-031A).

They moved to ``agentsec.images`` when the sandbox runner needed them at runtime rather
than only in tooling. Keeping one source of truth matters more than where it lives: two
copies of a digest drift, and a drifted digest silently changes what a published
benchmark ran against.

``scripts/toolbox.py`` and ``tests/test_compose.py`` import ``images`` by path, so this
re-export keeps them working without either learning about the move.
"""

from __future__ import annotations

from agentsec.images import (
    BUSYBOX,
    COMPOSE_IMAGES,
    GRAFANA,
    OPA,
    POSTGRES,
    PROMETHEUS,
    SEMGREP,
    TEMPORAL,
    TEMPORAL_UI,
    TOOL_IMAGES,
    TRIVY,
    Image,
)

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
