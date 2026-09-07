"""Persistent response cache for paid runs (AS-040 hardening).

**A response that has been paid for is never bought twice.**

This is the mechanism that makes a single funded run survivable. Every model response is
written to disk immediately, keyed by a fingerprint of the request. If the run dies at 80%
— a crash, a power cut, a Ctrl-C, a laptop lid — resuming replays the cached 80% for free
and buys only the remainder. Without it, a failure at 80% costs the whole budget and
delivers nothing.

It also makes a completed run **replayable**: the ablation can be re-scored, re-analysed,
or re-reported months later from the cache alone, with the API never contacted. That
matters more than convenience for a benchmark, because it means the numbers can be
recomputed without anyone having to trust that the run happened as described.

Three properties the design turns on:

**Writes are atomic.** Temp file plus rename, so a process killed mid-write leaves either
the old entry or the new one, never a truncated JSON document that poisons the resume it
was supposed to enable.

**The key covers everything that affects the answer.** Model, system prompt, messages,
purpose and the output schema. A cache that ignored the schema would serve a response
shaped for a different request.

**Cost is recorded with the entry.** So a resumed run can report what the *whole* run cost
rather than only what the resumed part cost — and a reader can see that the second half of
a number was paid for on a different day.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
from dataclasses import dataclass, field
from typing import Any, Final

from agentsec.agent.provider import ModelRequest, ModelResponse, Usage
from agentsec.log import get_logger

log = get_logger("agentsec.eval.cache")

CACHE_VERSION: Final = "1"


def request_key(request: ModelRequest) -> str:
    """A stable identity for a request.

    Covers every field that changes the answer. Sampling settings are excluded on purpose,
    the same way the mock provider's fingerprint excludes them: two calls differing only in
    temperature are the same question, and keying on them would cause a miss - which on a
    live run means a purchase - for a reason nobody would think to look for.
    """
    material = json.dumps(
        {
            "v": CACHE_VERSION,
            "model": request.model,
            "system": request.system,
            "messages": [[m.role, m.content] for m in request.messages],
            "purpose": request.purpose,
            "max_output_tokens": request.max_output_tokens,
            "schema": request.output_schema,
            "effort": request.effort.value if request.effort else None,
            "thinking_budget": request.thinking_budget,
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CachedResponse:
    """A response and what it cost to obtain."""

    key: str
    model: str
    text: str
    input_tokens: int
    output_tokens: int
    stop_reason: str
    usd: float
    latency_ms: float
    provider: str
    request_id: str | None = None
    parsed: dict[str, Any] | None = None

    def as_response(self) -> ModelResponse:
        return ModelResponse(
            model=self.model,
            text=self.text,
            usage=Usage(input_tokens=self.input_tokens, output_tokens=self.output_tokens),
            stop_reason=self.stop_reason,
            latency_ms=self.latency_ms,
            provider=self.provider,
            parsed=self.parsed,
            request_id=self.request_id,
            metadata={"cached": True, "original_usd": self.usd},
        )

    def as_document(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "model": self.model,
            "text": self.text,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "stop_reason": self.stop_reason,
            "usd": self.usd,
            "latency_ms": self.latency_ms,
            "provider": self.provider,
            "request_id": self.request_id,
            "parsed": self.parsed,
        }

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> CachedResponse:
        return cls(
            key=str(document["key"]),
            model=str(document["model"]),
            text=str(document.get("text", "")),
            input_tokens=int(document.get("input_tokens", 0)),
            output_tokens=int(document.get("output_tokens", 0)),
            stop_reason=str(document.get("stop_reason", "")),
            usd=float(document.get("usd", 0.0)),
            latency_ms=float(document.get("latency_ms", 0.0)),
            provider=str(document.get("provider", "")),
            request_id=document.get("request_id"),
            parsed=document.get("parsed"),
        )


@dataclass
class CacheStats:
    """Hits, misses, and what the hits were worth."""

    hits: int = 0
    misses: int = 0
    writes: int = 0
    usd_saved: float = 0.0
    corrupt_entries: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float | None:
        return self.hits / self.total if self.total else None

    def as_row(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "hit_rate": self.hit_rate,
            "usd_saved_by_cache": round(self.usd_saved, 6),
            "corrupt_entries": list(self.corrupt_entries),
        }


class ResponseCache:
    """A directory of paid-for responses.

    One file per response rather than a single index. A single file would have to be
    rewritten on every write, which is exactly when a crash would corrupt every entry
    rather than one — and the whole point of this cache is to survive a crash.
    """

    def __init__(self, directory: pathlib.Path, *, enabled: bool = True) -> None:
        self._directory = directory
        self._enabled = enabled
        self.stats = CacheStats()
        if enabled:
            directory.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> pathlib.Path:
        return self._directory

    def _path(self, key: str) -> pathlib.Path:
        # Two-level fan-out: a run can produce thousands of entries, and directories with
        # thousands of files are slow to list on Windows.
        return self._directory / key[:2] / f"{key}.json"

    def get(self, request: ModelRequest) -> CachedResponse | None:
        """Look up a paid-for response."""
        if not self._enabled:
            self.stats.misses += 1
            return None

        key = request_key(request)
        path = self._path(key)
        if not path.exists():
            self.stats.misses += 1
            return None

        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            entry = CachedResponse.from_document(document)
        except (json.JSONDecodeError, KeyError, ValueError, OSError) as error:
            # A corrupt entry is a miss, not a crash. It is also recorded: silently
            # re-buying a response that was already paid for is exactly the loss this
            # cache exists to prevent, so it should be visible in the artifact.
            log.warning("discarding a corrupt cache entry", key=key, error=str(error))
            self.stats.corrupt_entries.append(key)
            self.stats.misses += 1
            return None

        self.stats.hits += 1
        self.stats.usd_saved += entry.usd
        return entry

    def put(self, request: ModelRequest, response: ModelResponse, usd: float) -> CachedResponse:
        """Record a response the moment it arrives.

        Written before the caller does anything else with it. A response held in memory
        until the end of a cell is a response lost to a crash in that cell, and it was
        paid for.
        """
        key = request_key(request)
        entry = CachedResponse(
            key=key,
            model=response.model,
            text=response.text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            stop_reason=response.stop_reason,
            usd=usd,
            latency_ms=response.latency_ms,
            provider=response.provider,
            request_id=response.request_id,
            parsed=response.parsed,
        )
        if self._enabled:
            _write_atomic(self._path(key), entry.as_document())
            self.stats.writes += 1
        return entry

    def count(self) -> int:
        if not self._enabled or not self._directory.exists():
            return 0
        return sum(1 for _ in self._directory.rglob("*.json"))

    def total_usd(self) -> float:
        """What the whole cache cost, across every run that contributed to it.

        A resumed run reports this alongside its own spend, so a reader can see that half
        a number was paid for on a different day.
        """
        total = 0.0
        if not self._enabled or not self._directory.exists():
            return total
        for path in self._directory.rglob("*.json"):
            try:
                total += float(json.loads(path.read_text(encoding="utf-8")).get("usd", 0.0))
            except (json.JSONDecodeError, OSError, ValueError):
                continue
        return total


def _write_atomic(path: pathlib.Path, document: dict[str, Any]) -> None:
    """Write via a temp file and a rename.

    A process killed mid-write must leave either the old content or the new one. A
    truncated JSON document would poison the resume this cache exists to enable, which is
    the one failure it must not cause itself.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # delete=False and a manual replace, because the file has to outlive the handle: the
    # whole point is to rename it into place. A context manager cannot express that, which
    # is why SIM115 is suppressed here rather than worked around.
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=path.parent,
        prefix=f".{path.stem}.",
        suffix=".tmp",
        delete=False,
    )
    temporary = pathlib.Path(handle.name)
    try:
        with handle as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            # fsync before the rename. Without it the rename can be durable while the
            # contents are not, which on a crash leaves an empty file where a cached
            # response used to be - the exact loss this function exists to prevent.
            os.fsync(stream.fileno())
        # Path.replace maps to os.replace, which is atomic on both POSIX and Windows -
        # unlike Path.rename onto an existing target, which fails on Windows.
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


__all__ = [
    "CACHE_VERSION",
    "CacheStats",
    "CachedResponse",
    "ResponseCache",
    "request_key",
]
