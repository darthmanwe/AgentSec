"""Typed agent state and evidence rendering (AS-025).

The acceptance criterion is negative and it is the whole point: **there is no path by
which a raw context string reaches the planner.** Everything the model reads arrives as a
:class:`~agentsec.authz.models.ContextItem` carrying its source, its trust label and a
hash of the exact bytes seen. That type has no constructor producing context of unknown
origin, which is the structural form of "we never lost track of where this came from".

Why that matters more than it looks: the entire attack this project measures works by
getting attacker-authored text to be read as instruction. Anything that can append a bare
string to the prompt is a hole in the middle of the defence, and it is exactly the kind of
convenience that gets added at 2am to make a demo work.

**Untrusted evidence is fenced, labelled and escaped when rendered.** Fenced so the
boundary is visible to the model; labelled so it says what it is; escaped so a payload
cannot close the fence and continue outside it. That last one is the interesting case —
a corpus built to test injection will contain closing tags on purpose.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Final

from agentsec.authz.models import ContextItem, TrustLevel

EVIDENCE_OPEN: Final = "<untrusted-evidence"
EVIDENCE_CLOSE: Final = "</untrusted-evidence>"

#: Anything that could terminate the fence early, or open a new one. Neutralised rather
#: than rejected: a repository legitimately containing the word is not an attack, and
#: refusing to review it would be a denial of service with extra steps.
_FENCE = re.compile(r"</?untrusted-evidence[^>]*>", re.IGNORECASE)

MAX_ITEM_BYTES: Final = 32_000
MAX_TOTAL_BYTES: Final = 200_000


class StateError(Exception):
    """The agent state was used in a way that would lose provenance."""


@dataclass(frozen=True, slots=True)
class Hypothesis:
    """A model-generated claim about the repository. Never evidence for itself."""

    id: str
    statement: str
    confidence: str = "medium"
    supporting_item_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.statement.strip():
            raise StateError("a hypothesis needs a statement")


@dataclass(frozen=True, slots=True)
class ProposedAction:
    """One action the planner wants taken.

    Deliberately *not* :class:`~agentsec.authz.models.ActionIntent`. That type is the
    kernel's, validated against the trusted registry and carrying a risk class the registry
    assigns. This one is a wish, and turning a wish into an intent is a validation step
    that can fail — collapsing the two would let the planner name its own risk class.
    """

    tool: str
    operation: str
    resource: str
    arguments: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    hypothesis_id: str | None = None


@dataclass
class SecurityAgentState:
    """Everything one planning run knows.

    Mutable because the planning graph advances it node by node, but every *addition* goes
    through a method that enforces provenance. There is no ``context: list[str]`` for the
    same reason there is no ``execute()``: the type system is where an invariant survives
    a hurried change.
    """

    run_id: str
    task: str
    repository: str | None = None
    control_profile: str = "full"

    context: list[ContextItem] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    proposed: list[ProposedAction] = field(default_factory=list)
    denials: list[str] = field(default_factory=list)

    available_tools: tuple[str, ...] = ()
    resource_scope: tuple[str, ...] = ()

    iteration: int = 0
    max_iterations: int = 2
    notes: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ context

    def add_context(self, item: ContextItem) -> None:
        """Add one piece of evidence.

        The type is checked at runtime, not merely annotated. The first version of this
        method relied on the annotation plus a duplicate-id scan, and a test found the
        hole: with an empty context list the scan short-circuits, and a bare string was
        appended without complaint. An annotation constrains callers mypy can see; the
        planner's evidence comes from tool results and deserialised payloads, which are
        exactly the callers it cannot.

        This check *is* the acceptance criterion for AS-025 - there must be no path by
        which a raw context string reaches the planner.
        """
        if not isinstance(item, ContextItem):
            raise StateError(
                f"context must be a ContextItem carrying its provenance, not "
                f"{type(item).__name__}; evidence of unknown origin is how untrusted text "
                "ends up read as instruction"
            )
        if any(existing.id == item.id for existing in self.context):
            raise StateError(f"context item {item.id!r} is already present")
        self.context.append(item)

    def add_untrusted(self, item_id: str, source: str, content: str) -> ContextItem:
        """Convenience for the common case, which is always untrusted.

        The default is the safe label, and there is no matching ``add_trusted`` helper:
        trusted context comes from the registry and the policy bundle, which are loaded
        rather than gathered, so making it easy to mint would be making it easy to lie.
        """
        item = ContextItem(
            id=item_id,
            source=source,
            trust=TrustLevel.UNTRUSTED,
            content=content,
            retrieved_at=dt.datetime.now(dt.UTC),
        )
        self.add_context(item)
        return item

    @property
    def untrusted_count(self) -> int:
        return sum(1 for item in self.context if item.is_untrusted)

    def content_hashes(self) -> tuple[str, ...]:
        """Stable per-item hashes, in item-id order.

        Sorted by id rather than by insertion, so the same evidence gathered in a different
        order produces the same fingerprint — otherwise an approval bound to an evidence
        snapshot would fail to match a re-collection of identical facts.
        """
        return tuple(item.content_hash for item in sorted(self.context, key=lambda i: i.id))

    def evidence_digest(self) -> str:
        """One digest over the whole evidence set, for the approval context (AS-010)."""
        material = "\n".join(
            f"{item.id}\x1f{item.source}\x1f{item.trust.value}\x1f{item.content_hash}"
            for item in sorted(self.context, key=lambda i: i.id)
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ rendering

    def render_evidence(self) -> str:
        """Serialise evidence for a prompt, with every boundary explicit.

        Three things happen to every untrusted item, and dropping any one of them
        reintroduces the vulnerability:

        * it is **fenced**, so the model can see where attacker-controlled text starts;
        * it is **labelled** with its source and trust level, so the fence says what it is;
        * fence-like sequences inside the content are **neutralised**, so a payload cannot
          close the fence early and continue as if it were outside.

        The third is the one a test corpus will attack directly, because it is the one
        most implementations forget.
        """
        blocks: list[str] = []
        budget = MAX_TOTAL_BYTES

        for item in sorted(self.context, key=lambda i: i.id):
            body, truncated = _clip(neutralise(item.content), min(MAX_ITEM_BYTES, budget))
            budget -= len(body.encode("utf-8"))
            attributes = (
                f' id="{_attr(item.id)}" source="{_attr(item.source)}"'
                f' trust="{item.trust.value}" sha256="{item.content_hash[:16]}"'
            )
            note = " (truncated)" if truncated else ""
            blocks.append(f"{EVIDENCE_OPEN}{attributes}{note}>\n{body}\n{EVIDENCE_CLOSE}")
            if budget <= 0:
                blocks.append("[evidence truncated: total size limit reached]")
                break

        return "\n\n".join(blocks) if blocks else "[no evidence was gathered]"

    def render_tools(self) -> str:
        """The tools that exist, as far as the model is concerned."""
        return "\n".join(f"- {name}" for name in self.available_tools) or "- (none)"

    def render_scope(self) -> str:
        return "\n".join(f"- {resource}" for resource in self.resource_scope) or "- (none)"

    # ------------------------------------------------------------------ progress

    def record_denial(self, reason: str) -> None:
        self.denials.append(reason)

    def may_replan(self) -> bool:
        """Bounded. An unbounded replan loop against a policy that keeps refusing is a
        way to spend a budget without producing a result."""
        return self.iteration < self.max_iterations

    def snapshot(self) -> dict[str, Any]:
        """What goes into the run record and the evaluation artifact."""
        return {
            "run_id": self.run_id,
            "task": self.task,
            "repository": self.repository,
            "control_profile": self.control_profile,
            "context_items": len(self.context),
            "untrusted_items": self.untrusted_count,
            "evidence_digest": self.evidence_digest(),
            "hypotheses": len(self.hypotheses),
            "proposed_actions": len(self.proposed),
            "denials": list(self.denials),
            "iteration": self.iteration,
        }


def neutralise(content: str) -> str:
    """Defuse fence sequences in untrusted content.

    Replaced with a visible marker rather than stripped, so a reader of the transcript can
    see that something was defused. Silently deleting it would hide the most interesting
    thing in an injection corpus.
    """
    return _FENCE.sub("[fence-sequence-removed]", content)


def _attr(value: str) -> str:
    """Escape a value for an XML-ish attribute. Quotes and angle brackets only — this is
    a prompt, not a document, and over-escaping makes the evidence harder for the model to
    read without making it safer."""
    return (
        value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _clip(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[: max(0, limit)].decode("utf-8", "ignore"), True


__all__ = [
    "EVIDENCE_CLOSE",
    "EVIDENCE_OPEN",
    "MAX_ITEM_BYTES",
    "MAX_TOTAL_BYTES",
    "Hypothesis",
    "ProposedAction",
    "SecurityAgentState",
    "StateError",
    "neutralise",
]
